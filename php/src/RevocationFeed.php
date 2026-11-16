<?php

declare(strict_types=1);

namespace Gatekeeper;

use Psr\SimpleCache\CacheInterface;

/**
 * The revocation feed for PHP (FR-S17, ADR-0123): FPM workers are short-lived,
 * so instead of holding the stream this polls the snapshot into the cache
 * every few seconds; with Laravel's cache store every worker shares it.
 * Bind it as the DenylistChecker. While the copy is stale, denied() throws,
 * which refuses the token (fail closed).
 */
final class RevocationFeed implements DenylistChecker
{
    private CacheInterface $cache;

    /** @var callable(string, array<string, string>, ?string=): array{0: int, 1: string, 2?: array<string, string>} */
    private $fetch;

    private string $key;

    private int $maxStale;

    /**
     * @param ClientCredentials $credentials a client allowed the revocations:read scope
     * @param ?callable(string, array<string, string>, ?string=): array{0: int, 1: string, 2?: array<string, string>} $fetch tests inject one
     */
    public function __construct(
        private readonly string $issuer,
        private readonly ClientCredentials $credentials,
        ?CacheInterface $cache = null,
        ?callable $fetch = null,
        private readonly int $pollSeconds = 5,
        int $maxStaleSeconds = 60,
    ) {
        $this->cache = $cache ?? new ArrayCache();
        $this->fetch = $fetch ?? Gatekeeper::http(...);
        $this->key = 'gatekeeper.revfeed.' . hash('sha256', rtrim($issuer, '/'));
        $this->maxStale = max(10, min(300, $maxStaleSeconds));
    }

    public function denied(string $sid, string $jti): bool
    {
        $now = time();
        $state = $this->cache->get($this->key);
        $at = is_array($state) ? (int) ($state['at'] ?? 0) : 0;
        // shortcut: has-then-set isn't atomic, so a few workers may poll at once at the boundary; fine for a 5 s poll
        if ($now - $at >= $this->pollSeconds && !$this->cache->has($this->key . '.lock')) {
            $this->cache->set($this->key . '.lock', 1, $this->pollSeconds);
            $state = $this->refresh($now) ?? $state;
        }
        if (!is_array($state) || $now - (int) ($state['at'] ?? 0) > $this->maxStale) {
            throw new \RuntimeException('gatekeeper: the revocation feed is stale');
        }
        foreach (['sid:' . $sid => $sid, 'jti:' . $jti => $jti] as $k => $v) {
            if ($v !== '' && ($state['set'][$k] ?? 0) > $now) {
                return true;
            }
        }
        return false;
    }

    /** @return ?array{at: int, set: array<string, int>} the new copy, or null when Gatekeeper couldn't be reached */
    private function refresh(int $now): ?array
    {
        try {
            $token = $this->credentials->token();
        } catch (\RuntimeException) {
            return null;
        }
        [$status, $body] = ($this->fetch)(rtrim($this->issuer, '/') . '/v1/revocations',
            ['Authorization' => 'Bearer ' . $token, 'Accept' => 'application/json']);
        $snap = json_decode($body, true);
        if ($status !== 200 || !is_array($snap) || !is_array($snap['items'] ?? null)) {
            return null;
        }
        $set = [];
        foreach ($snap['items'] as $r) {
            $until = strtotime((string) ($r['until'] ?? ''));
            if (is_array($r) && $until !== false) {
                $set[($r['kind'] ?? '') . ':' . ($r['value'] ?? '')] = $until;
            }
        }
        $state = ['at' => $now, 'set' => $set];
        $this->cache->set($this->key, $state, 3600);
        return $state;
    }
}
