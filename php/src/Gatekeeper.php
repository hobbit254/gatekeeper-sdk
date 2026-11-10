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

    /** @var callable(string, array<string, string>): array{int, string} */
    private $fetch;

    /**
     * @param ?CacheInterface $cache holds the JWKS and role map (Laravel's cache store, or per-process memory)
     * @param ?callable(string, array<string, string>): array{int, string} $fetch returns [status, body]; tests inject one
     */
    public function __construct(
        private readonly Config $config,
        ?CacheInterface $cache = null,
        ?callable $fetch = null,
        private readonly ?DenylistChecker $denylist = null,
    ) {
        $this->cache = $cache ?? new ArrayCache();
        $this->fetch = $fetch ?? self::httpGet(...);
    }

    /** Runs the TOKENS.md checklist and returns the Principal. */
    public function verify(string $token): Principal
    {
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
    private static function httpGet(string $url, array $headers): array
    {
        $lines = [];
        foreach ($headers as $k => $v) {
            $lines[] = "{$k}: {$v}";
        }
        $ctx = stream_context_create(['http' => ['method' => 'GET', 'header' => implode("\r\n", $lines),
            'timeout' => 5, 'ignore_errors' => true]]);
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
