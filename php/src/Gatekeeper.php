<?php

declare(strict_types=1);

namespace Gatekeeper;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Psr\SimpleCache\CacheInterface;

/**
 * Verifies access tokens offline, hydrates a Principal and resolves
 * permissions from the client's role map (docs/INTEGRATION.md, docs/TOKENS.md,
 * ADR-0005, ADR-0038).
 */
final class Gatekeeper
{
    private const JWKS_TTL = 3600;
    private const JWKS_COOLDOWN = 30;

    private CacheInterface $cache;

    private const KEY_TTL = 60; // a revoked key works this long at most (ADR-0059)
    private const DEAD_KEY_TTL = 10;

    /** @var callable(string, array<string, string>, ?string=): array{int, string} */
    private $fetch;

    /**
     * @param ?CacheInterface $cache holds the JWKS and role map (Laravel's cache store, or per-process memory)
     * @param ?callable(string, array<string, string>, ?string=): array{int, string} $fetch returns [status, body]; a body means POST; tests inject one
     */
    public function __construct(
        private readonly Config $config,
        ?CacheInterface $cache = null,
        ?callable $fetch = null,
        private readonly ?DenylistChecker $denylist = null,
    ) {
        $this->cache = $cache ?? new ArrayCache();
        $this->fetch = $fetch ?? self::http(...);
    }

    /** Runs the TOKENS.md checklist and returns the Principal. */
    public function verify(string $token): Principal
    {
        if (str_starts_with($token, 'gk_live_')) {
            return $this->verifyKey($token);
        }
        $claims = $this->claims($token);
        $sid = (string) ($claims->sid ?? '');
        $jti = (string) ($claims->jti ?? '');
        if ($this->denylist !== null) {
            try {
                $denied = $this->denylist->denied($sid, $jti);
            } catch (\Throwable $e) {
                throw new InvalidTokenException('denylist unavailable', 0, $e); // fail closed (ADR-0048)
            }
            if ($denied) {
                throw new InvalidTokenException('revoked');
            }
        }
        $roles = self::strings($claims->roles ?? []);
        $rv = is_int($claims->rv ?? null) ? $claims->rv : 0;

        return new Principal(
            sub: (string) ($claims->sub ?? ''),
            tenantId: (string) ($claims->tid ?? ''),
            orgId: isset($claims->org) && is_string($claims->org) ? $claims->org : null,
            clientId: (string) ($claims->client_id ?? ''),
            roles: $roles,
            permissions: $this->permissions($roles, $rv),
            scopes: array_values(array_filter(explode(' ', (string) ($claims->scope ?? '')))),
            amr: self::strings($claims->amr ?? []),
            authTime: is_int($claims->auth_time ?? null) ? $claims->auth_time : 0,
            rv: $rv,
            sid: $sid,
            jti: $jti,
            actor: isset($claims->act->sub) && is_string($claims->act->sub) ? $claims->act->sub : null,
            impersonationEndsAt: isset($claims->act->ends_at) && is_int($claims->act->ends_at) ? $claims->act->ends_at : null,
        );
    }

    /**
     * Introspects an API key with this API's client credentials, caching the
     * answer; any failure refuses (ADR-0057, ADR-0059).
     */
    private function verifyKey(string $key): Principal
    {
        $cacheKey = 'gatekeeper.apikey.' . hash('sha256', $this->config->issuer . '|' . $key);
        $r = $this->cache->get($cacheKey);
        if (!is_array($r)) {
            $headers = ['Content-Type' => 'application/x-www-form-urlencoded', 'Accept' => 'application/json',
                'Authorization' => 'Basic ' . base64_encode($this->config->clientId . ':' . $this->config->clientSecret)];
            try {
                [$status, $body] = ($this->fetch)($this->config->issuer . '/oauth2/introspect', $headers, http_build_query(['token' => $key]));
            } catch (\Throwable $e) {
                throw new InvalidTokenException('introspection failed', 0, $e);
            }
            $r = json_decode($body, true);
            if ($status !== 200 || !is_array($r)) {
                throw new InvalidTokenException("introspection failed: status {$status}");
            }
            $live = ($r['active'] ?? false) === true && ($r['token_type'] ?? '') === 'api_key';
            $this->cache->set($cacheKey, $r, $live ? self::KEY_TTL : self::DEAD_KEY_TTL);
        }
        if (($r['active'] ?? false) !== true || ($r['token_type'] ?? '') !== 'api_key') {
            throw new InvalidTokenException('inactive API key');
        }
        return new Principal(
            sub: (string) ($r['sub'] ?? ''),
            tenantId: (string) ($r['tid'] ?? ''),
            orgId: null,
            clientId: '',
            roles: [],
            permissions: self::strings($r['permissions'] ?? []),
            scopes: array_values(array_filter(explode(' ', (string) ($r['scope'] ?? '')))),
            amr: [],
            authTime: 0,
            rv: 0,
            apiKey: true,
            ownerType: (string) ($r['owner_type'] ?? ''),
        );
    }

    private function claims(string $token): \stdClass
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            throw new InvalidTokenException('malformed');
        }
        $header = json_decode(JWT::urlsafeB64Decode($parts[0]));
        if (!$header instanceof \stdClass || ($header->alg ?? '') !== 'ES256' || strcasecmp((string) ($header->typ ?? ''), 'at+jwt') !== 0) {
            throw new InvalidTokenException('header: want alg ES256, typ at+jwt');
        }
        $kid = (string) ($header->kid ?? '');
        $keys = $this->keys(false);
        if (!isset($keys[$kid])) {
            $keys = $this->keys(true); // unknown kid: one refetch, at most every 30 s
        }
        if (!isset($keys[$kid])) {
            throw new InvalidTokenException('unknown kid');
        }

        $previous = JWT::$leeway; // php-jwt's leeway is static: restore it for other code in the process
        JWT::$leeway = max(0, min($this->config->leewaySec, 60));
        try {
            $claims = JWT::decode($token, $keys);
        } catch (\Throwable $e) {
            throw new InvalidTokenException($e->getMessage(), 0, $e);
        } finally {
            JWT::$leeway = $previous;
        }
        if (!isset($claims->exp)) {
            throw new InvalidTokenException('exp missing');
        }
        if (($claims->iss ?? null) !== $this->config->issuer) {
            throw new InvalidTokenException('iss');
        }
        $aud = is_array($claims->aud ?? null) ? $claims->aud : [$claims->aud ?? null];
        if (!in_array($this->config->audience, $aud, true)) {
            throw new InvalidTokenException('aud');
        }
        return $claims;
    }

    /** @return array<string, \Firebase\JWT\Key> */
    private function keys(bool $refresh): array
    {
        $cacheKey = 'gatekeeper.jwks.' . sha1($this->config->issuer);
        $jwks = $this->cache->get($cacheKey);
        if ($jwks === null || ($refresh && time() - ($jwks['fetched'] ?? 0) >= self::JWKS_COOLDOWN)) {
            $jwks = ['set' => $this->getJSON($this->config->issuer . '/.well-known/jwks.json', false), 'fetched' => time()];
            $this->cache->set($cacheKey, $jwks, self::JWKS_TTL);
        }
        return JWK::parseKeySet($jwks['set'], 'ES256');
    }

    /**
     * Resolves roles through the cached role map, refetching when the token's
     * rv is newer than the cached one.
     *
     * @param list<string> $roles
     * @return list<string>
     */
    private function permissions(array $roles, int $rv): array
    {
        $cacheKey = 'gatekeeper.rolemap.' . sha1($this->config->issuer . '|' . $this->config->clientId);
        $map = $this->cache->get($cacheKey);
        if ($map === null || $rv > ($map['rv'] ?? 0)) {
            $map = $this->getJSON($this->config->issuer . '/v1/clients/' . rawurlencode($this->config->clientId) . '/role-map', true);
            $this->cache->set($cacheKey, $map);
        }
        $out = [];
        foreach ($roles as $role) {
            foreach ($map['roles'][$role] ?? [] as $p) {
                $out[$p] = true;
            }
        }
        return array_keys($out);
    }

    /** @return array<string, mixed> */
    private function getJSON(string $url, bool $auth): array
    {
        $headers = ['Accept' => 'application/json'];
        if ($auth && $this->config->clientSecret !== '') {
            $headers['Authorization'] = 'Basic ' . base64_encode($this->config->clientId . ':' . $this->config->clientSecret);
        }
        [$status, $body] = ($this->fetch)($url, $headers);
        $data = json_decode($body, true);
        if ($status !== 200 || !is_array($data)) {
            throw new \RuntimeException("gatekeeper: fetch {$url}: status {$status}");
        }
        return $data;
    }

    /**
     * @param array<string, string> $headers
     * @return array{int, string}
     */
    public static function http(string $url, array $headers, ?string $body = null): array
    {
        $lines = [];
        foreach ($headers as $k => $v) {
            $lines[] = "{$k}: {$v}";
        }
        $opts = ['method' => $body === null ? 'GET' : 'POST', 'header' => implode("\r\n", $lines), 'timeout' => 5, 'ignore_errors' => true];
        if ($body !== null) {
            $opts['content'] = $body;
        }
        $ctx = stream_context_create(['http' => $opts]);
        $body = @file_get_contents($url, false, $ctx);
        $status = 0;
        foreach ($http_response_header ?? [] as $h) {
            if (preg_match('#^HTTP/\S+ (\d{3})#', $h, $m)) {
                $status = (int) $m[1];
            }
        }
        return [$status, $body === false ? '' : $body];
    }

    /** @return list<string> */
    private static function strings(mixed $v): array
    {
        return is_array($v) ? array_values(array_filter($v, 'is_string')) : [];
    }
}
