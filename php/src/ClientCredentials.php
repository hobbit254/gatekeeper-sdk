<?php

declare(strict_types=1);

namespace Gatekeeper;

use Psr\SimpleCache\CacheInterface;

/**
 * Fetches and caches an m2m access token (FR-M1, ADR-0059). The token is
 * reused until a minute before it expires; with Laravel's cache store every
 * worker shares it.
 */
final class ClientCredentials
{
    private CacheInterface $cache;

    /** @var callable(string, array<string, string>, ?string=): array{int, string} */
    private $fetch;

    /** @param ?callable(string, array<string, string>, ?string=): array{int, string} $fetch returns [status, body]; tests inject one */
    public function __construct(
        private readonly string $tokenUrl,
        private readonly string $clientId,
        private readonly string $clientSecret,
        private readonly string $scope = '',
        private readonly string $audience = '',
        ?CacheInterface $cache = null,
        ?callable $fetch = null,
    ) {
        $this->cache = $cache ?? new ArrayCache();
        $this->fetch = $fetch ?? Gatekeeper::http(...);
    }

    /** Returns an access token valid for at least another minute. */
    public function token(): string
    {
        $key = 'gatekeeper.cc.' . hash('sha256', $this->tokenUrl . '|' . $this->clientId . '|' . $this->scope . '|' . $this->audience);
        $cached = $this->cache->get($key);
        if (is_string($cached) && $cached !== '') {
            return $cached;
        }
        $form = ['grant_type' => 'client_credentials'];
        if ($this->scope !== '') {
            $form['scope'] = $this->scope;
        }
        if ($this->audience !== '') {
            $form['audience'] = $this->audience;
        }
        $headers = ['Content-Type' => 'application/x-www-form-urlencoded', 'Accept' => 'application/json',
            'Authorization' => 'Basic ' . base64_encode(rawurlencode($this->clientId) . ':' . rawurlencode($this->clientSecret))];
        [$status, $body] = ($this->fetch)($this->tokenUrl, $headers, http_build_query($form));
        $r = json_decode($body, true);
        if ($status !== 200 || !is_array($r) || !is_string($r['access_token'] ?? null)) {
            throw new \RuntimeException("gatekeeper: client credentials: status {$status}");
        }
        $ttl = max(1, (int) ($r['expires_in'] ?? 0) - 60);
        $this->cache->set($key, $r['access_token'], $ttl);
        return $r['access_token'];
    }
}
