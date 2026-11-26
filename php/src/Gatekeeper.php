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

    /** @var callable(string, array<string, string>, ?string=): array{0: int, 1: string, 2?: array<string, string>} */
    private $fetch;

    /**
     * @param ?CacheInterface $cache holds the JWKS and role map (Laravel's cache store, or per-process memory)
     * @param ?callable(string, array<string, string>, ?string=): array{0: int, 1: string, 2?: array<string, string>} $fetch returns [status, body, lowercased response headers]; a body means POST; tests inject one
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
        $orv = is_int($claims->orv ?? null) ? $claims->orv : 0;
        $org = isset($claims->org) && is_string($claims->org) ? $claims->org : '';
        [$permissions, $stepUp] = $this->permissions($roles, $rv, $org, $orv);

        return new Principal(
            sub: (string) ($claims->sub ?? ''),
            tenantId: (string) ($claims->tid ?? ''),
            orgId: isset($claims->org) && is_string($claims->org) ? $claims->org : null,
            clientId: (string) ($claims->client_id ?? ''),
            roles: $roles,
            permissions: $permissions,
            scopes: array_values(array_filter(explode(' ', (string) ($claims->scope ?? '')))),
            amr: self::strings($claims->amr ?? []),
            authTime: is_int($claims->auth_time ?? null) ? $claims->auth_time : 0,
            rv: $rv,
            orv: $orv,
            sid: $sid,
            jti: $jti,
            actor: isset($claims->act->sub) && is_string($claims->act->sub) ? $claims->act->sub : null,
            impersonationEndsAt: isset($claims->act->ends_at) && is_int($claims->act->ends_at) ? $claims->act->ends_at : null,
            jkt: isset($claims->cnf->jkt) && is_string($claims->cnf->jkt) ? $claims->cnf->jkt : '',
            stepUp: $stepUp,
            entitlements: self::entitlements($claims->entitlements ?? null),
        );
    }

    private const DPOP_SKEW = 60;
    private const DPOP_ALGS = ['ES256', 'RS256', 'EdDSA'];

    /** ID tokens and userinfo JWTs: EdDSA for clients that opt in (ADR-0124). */
    private const ID_TOKEN_ALGS = ['ES256', 'EdDSA'];

    /**
     * Checks a request's DPoP proof for a DPoP-bound principal (RFC 9449,
     * ADR-0070): signed by the bound key, for this method and URL (query
     * ignored), with ath of $accessToken, iat within 60 s, a jti not seen before.
     */
    public function verifyDPoP(Principal $p, string $accessToken, string $proof, string $method, string $url, ?int $now = null): void
    {
        $now ??= time();
        if ($p->jkt === '') {
            throw new InvalidTokenException('DPoP: the token is not DPoP-bound');
        }
        $parts = explode('.', $proof);
        $header = count($parts) === 3 ? json_decode(JWT::urlsafeB64Decode($parts[0]), true) : null;
        $jwk = is_array($header) ? ($header['jwk'] ?? null) : null;
        $alg = is_array($header) ? (string) ($header['alg'] ?? '') : '';
        if (!is_array($jwk) || ($header['typ'] ?? '') !== 'dpop+jwt' || isset($jwk['d']) || !in_array($alg, self::DPOP_ALGS, true)) {
            throw new InvalidTokenException('DPoP: header');
        }
        [$previousTime, $previousLeeway] = [JWT::$timestamp, JWT::$leeway]; // php-jwt's clock is static: restore it
        [JWT::$timestamp, JWT::$leeway] = [$now, self::DPOP_SKEW];
        try {
            $claims = (array) JWT::decode($proof, JWK::parseKey($jwk, $alg));
        } catch (\Throwable $e) {
            throw new InvalidTokenException('DPoP: signature', 0, $e);
        } finally {
            [JWT::$timestamp, JWT::$leeway] = [$previousTime, $previousLeeway];
        }
        if (($claims['htm'] ?? null) !== $method || !is_string($claims['htu'] ?? null) || self::htu($claims['htu']) === null
            || self::htu($claims['htu']) !== self::htu($url)) {
            throw new InvalidTokenException('DPoP: htm or htu');
        }
        if (!is_int($claims['iat'] ?? null) || abs($claims['iat'] - $now) > self::DPOP_SKEW) {
            throw new InvalidTokenException('DPoP: iat');
        }
        if (!hash_equals(JWT::urlsafeB64Encode(hash('sha256', $accessToken, true)), (string) ($claims['ath'] ?? ''))) {
            throw new InvalidTokenException('DPoP: ath');
        }
        if (!hash_equals($p->jkt, self::thumbprint($jwk))) {
            throw new InvalidTokenException('DPoP: another key');
        }
        $jti = $claims['jti'] ?? '';
        $seen = 'gatekeeper.dpop.' . hash('sha256', $p->jkt . ':' . (is_string($jti) ? $jti : ''));
        if (!is_string($jti) || $jti === '' || $this->cache->has($seen)) {
            throw new InvalidTokenException('DPoP: replayed');
        }
        $this->cache->set($seen, true, 2 * self::DPOP_SKEW);
    }

    /** A URL without query and fragment, as htu compares it, or null. */
    private static function htu(string $url): ?string
    {
        $u = parse_url($url);
        if (!is_array($u) || !isset($u['scheme'], $u['host'])) {
            return null;
        }
        return strtolower($u['scheme']) . '://' . strtolower($u['host']) . (isset($u['port']) ? ':' . $u['port'] : '') . ($u['path'] ?? '/');
    }

    /** RFC 7638 SHA-256 JWK thumbprint, base64url. @param array<string, mixed> $jwk */
    public static function thumbprint(array $jwk): string
    {
        $members = match ($jwk['kty'] ?? '') {
            'EC' => ['crv', 'kty', 'x', 'y'],
            'RSA' => ['e', 'kty', 'n'],
            'OKP' => ['crv', 'kty', 'x'],
            default => throw new InvalidTokenException('DPoP: key type'),
        };
        $req = [];
        foreach ($members as $m) {
            $req[$m] = (string) ($jwk[$m] ?? '');
        }
        return JWT::urlsafeB64Encode(hash('sha256', (string) json_encode($req, JSON_UNESCAPED_SLASHES), true));
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

    /**
     * Verifies a signed JWT from the issuer for $audience (default: this API); $typ null skips the typ check.
     * Access tokens allow only ES256; ID tokens and userinfo also EdDSA (ADR-0124). php-jwt refuses a key
     * whose alg differs from the header's, so a header can't borrow the other ring's key.
     *
     * @param list<string> $algs
     */
    private function claims(string $token, ?string $typ = 'at+jwt', ?string $audience = null, array $algs = ['ES256']): \stdClass
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            throw new InvalidTokenException('malformed');
        }
        $header = json_decode(JWT::urlsafeB64Decode($parts[0]));
        if (!$header instanceof \stdClass || !in_array($header->alg ?? '', $algs, true) || ($typ !== null && strcasecmp((string) ($header->typ ?? ''), $typ) !== 0)) {
            throw new InvalidTokenException('header: want alg ' . implode(' or ', $algs) . ($typ !== null ? ", typ {$typ}" : ''));
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
        if (!in_array($audience ?? $this->config->audience, $aud, true)) {
            throw new InvalidTokenException('aud');
        }
        return $claims;
    }

    /**
     * Checks an ID token issued to this client (clientId), decrypting it first
     * when it is encrypted to the client's key (FR-S15, ADR-0121).
     *
     * @return array<string, mixed>
     * @throws InvalidTokenException
     */
    public function verifyIdToken(string $raw, ?string $nonce = null): array
    {
        $claims = (array) $this->claims($this->innerToken($raw), null, $this->config->clientId, self::ID_TOKEN_ALGS);
        if ($nonce !== null && ($claims['nonce'] ?? null) !== $nonce) {
            throw new InvalidTokenException('nonce');
        }
        return $claims;
    }

    /**
     * Fetches the user's claims with $accessToken; an encrypted answer
     * (application/jwt) is decrypted and checked like an ID token.
     *
     * @return array<string, mixed>
     */
    public function userInfo(string $accessToken): array
    {
        [$status, $body, $headers] = ($this->fetch)($this->config->issuer . '/oauth2/userinfo',
            ['Accept' => 'application/json, application/jwt', 'Authorization' => 'Bearer ' . $accessToken]) + [2 => []];
        if ($status !== 200) {
            throw new InvalidTokenException("userinfo: status {$status}");
        }
        if (str_starts_with((string) ($headers['content-type'] ?? ''), 'application/jwt')) {
            return (array) $this->claims($this->innerToken(trim($body)), null, $this->config->clientId, self::ID_TOKEN_ALGS);
        }
        $data = json_decode($body, true);
        return is_array($data) ? $data : throw new InvalidTokenException('userinfo: not JSON');
    }

    /** The signed JWT inside $raw: $raw itself, or $raw decrypted with Config::$decryptionKey. */
    private function innerToken(string $raw): string
    {
        if (count(explode('.', $raw)) !== 5) {
            return $raw;
        }
        if ($this->config->decryptionKey === '') {
            throw new InvalidTokenException('encrypted, and no decryptionKey is configured');
        }
        try {
            $jwe = (new \Jose\Component\Encryption\Serializer\CompactSerializer())->unserialize($raw);
            $algorithms = new \Jose\Component\Core\AlgorithmManager([
                new \Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHESA256KW(),
                new \Jose\Component\Encryption\Algorithm\KeyEncryption\RSAOAEP256(),
                new \Jose\Component\Encryption\Algorithm\ContentEncryption\A256GCM(),
            ]);
            $key = \Jose\Component\KeyManagement\JWKFactory::createFromKey($this->config->decryptionKey);
            if (!(new \Jose\Component\Encryption\JWEDecrypter($algorithms))->decryptUsingKey($jwe, $key, 0)) {
                throw new InvalidTokenException('decrypt');
            }
        } catch (InvalidTokenException $e) {
            throw $e;
        } catch (\Throwable $e) {
            throw new InvalidTokenException('decrypt', 0, $e);
        }
        return (string) $jwe->getPayload();
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

    /** Marks an organization's own role in a token's roles (ADR-0142). */
    public const ORG_ROLE_PREFIX = 'org/';

    /**
     * Resolves roles through the cached role map, refetching when the token's
     * rv is newer than the cached one. A token in an organization holding one
     * of its own roles (org/<name>) is resolved through that organization's
     * map, cached by (org, rv, orv) (ADR-0142).
     *
     * @param list<string> $roles
     * @return array{list<string>, array<string, int>} permissions and their step-up windows (ADR-0097)
     */
    private function permissions(array $roles, int $rv, string $org = '', int $orv = 0): array
    {
        $url = $this->config->issuer . '/v1/clients/' . rawurlencode($this->config->clientId) . '/role-map';
        $cacheKey = 'gatekeeper.rolemap.' . sha1($this->config->issuer . '|' . $this->config->clientId);
        $hasOrgRole = false;
        foreach ($roles as $role) {
            $hasOrgRole = $hasOrgRole || str_starts_with($role, self::ORG_ROLE_PREFIX);
        }
        if ($org !== '' && $hasOrgRole) {
            $cacheKey .= '.org.' . sha1($org);
            $url .= '?org=' . rawurlencode($org);
        }
        $map = $this->cache->get($cacheKey);
        if ($map === null || $rv > ($map['rv'] ?? 0) || $orv > ($map['orv'] ?? 0)) {
            $map = $this->getJSON($url, true);
            $this->cache->set($cacheKey, $map);
        }
        $out = [];
        foreach ($roles as $role) {
            if ($org === '' && str_starts_with($role, self::ORG_ROLE_PREFIX)) {
                continue; // an organization's role means nothing outside it
            }
            foreach ($map['roles'][$role] ?? [] as $p) {
                $out[$p] = true;
            }
        }
        $stepUp = [];
        foreach ($map['step_up'] ?? [] as $p => $sec) {
            if (is_int($sec) && $sec > 0) {
                $stepUp[(string) $p] = $sec;
            }
        }
        return [array_keys($out), $stepUp];
    }

    /**
     * Asks Gatekeeper whether $token's subject holds $permission on $resource
     * ("campaign:42"), roles and relations; never cached (FR-Z12, ADR-0108).
     *
     * @return array{allow: bool, matched_by: string, max_age?: int}
     * @throws \RuntimeException when Gatekeeper can't answer
     */
    public function canOn(string $token, string $permission, string $resource): array
    {
        return $this->authz($token, '/v1/authz/check', ['permission' => $permission, 'resource' => $resource]);
    }

    /**
     * canOn for many resources, in order, 200 to a request.
     *
     * @param list<string> $resources
     * @return list<array{allow: bool, matched_by: string, max_age?: int}>
     */
    public function canOnEach(string $token, string $permission, array $resources): array
    {
        $out = [];
        foreach (array_chunk($resources, 200) as $chunk) {
            $r = $this->authz($token, '/v1/authz/check-batch', ['checks' => array_map(
                fn (string $res) => ['permission' => $permission, 'resource' => $res], $chunk)]);
            if (!is_array($r['results'] ?? null) || count($r['results']) !== count($chunk)) {
                throw new \RuntimeException('gatekeeper: resource check unavailable: wrong number of answers');
            }
            array_push($out, ...$r['results']);
        }
        return $out;
    }

    /**
     * canOn for $userId with this client's own credentials (scope authz:check),
     * for users whose tokens are DPoP-bound (FR-Z16, ADR-0119).
     *
     * @return array{allow: bool, matched_by: string, max_age?: int}
     * @throws NotServedException when the user has no live sign-in through this client
     * @throws \RuntimeException when Gatekeeper can't answer
     */
    public function canOnFor(string $userId, string $permission, string $resource): array
    {
        return $this->authz($this->clientToken(), '/v1/authz/check', ['user_id' => $userId, 'permission' => $permission, 'resource' => $resource]);
    }

    /**
     * canOnFor for many resources, in order, 200 to a request.
     *
     * @param list<string> $resources
     * @return list<array{allow: bool, matched_by: string, max_age?: int}>
     */
    public function canOnEachFor(string $userId, string $permission, array $resources): array
    {
        $token = $this->clientToken();
        $out = [];
        foreach (array_chunk($resources, 200) as $chunk) {
            $r = $this->authz($token, '/v1/authz/check-batch', ['user_id' => $userId, 'checks' => array_map(
                fn (string $res) => ['permission' => $permission, 'resource' => $res], $chunk)]);
            if (!is_array($r['results'] ?? null) || count($r['results']) !== count($chunk)) {
                throw new \RuntimeException('gatekeeper: resource check unavailable: wrong number of answers');
            }
            array_push($out, ...$r['results']);
        }
        return $out;
    }

    /** Whether on-behalf checks can be made: a client secret is configured. */
    public function checksOnBehalf(): bool
    {
        return $this->config->clientSecret !== '';
    }

    private ?ClientCredentials $authzClient = null;

    private function clientToken(): string
    {
        if (!$this->checksOnBehalf()) {
            throw new \LogicException('gatekeeper: on-behalf checks need clientId and clientSecret');
        }
        $this->authzClient ??= new ClientCredentials($this->config->issuer . '/oauth2/token', $this->config->clientId,
            $this->config->clientSecret, 'authz:check', $this->config->audience, null, $this->fetch);
        return $this->authzClient->token();
    }

    /** @return array<string, mixed> */
    private function authz(string $token, string $path, array $body): array
    {
        [$status, $raw] = ($this->fetch)($this->config->issuer . $path,
            ['Content-Type' => 'application/json', 'Accept' => 'application/json', 'Authorization' => 'Bearer ' . $token], json_encode($body));
        $data = json_decode($raw, true);
        if ($status === 403 && is_array($data) && str_ends_with((string) ($data['type'] ?? ''), 'user-not-served')) {
            throw new NotServedException('gatekeeper: the user has no live sign-in through this client');
        }
        if ($status !== 200 || !is_array($data)) {
            throw new \RuntimeException("gatekeeper: resource check unavailable: status {$status}");
        }
        return $data;
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
     * @return array{0: int, 1: string, 2?: array<string, string>}
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
        $got = [];
        foreach ($http_response_header ?? [] as $h) {
            if (preg_match('#^HTTP/\S+ (\d{3})#', $h, $m)) {
                [$status, $got] = [(int) $m[1], []]; // a redirect starts a new response
            } elseif (str_contains($h, ':')) {
                [$k, $v] = explode(':', $h, 2);
                $got[strtolower(trim($k))] = trim($v);
            }
        }
        return [$status, $body === false ? '' : $body, $got];
    }

    /** @return array{plan: string, features: list<string>}|null */
    private static function entitlements(mixed $e): ?array
    {
        if (!is_object($e) || !is_string($e->plan ?? null) || !is_array($e->features ?? null)) {
            return null;
        }
        return ['plan' => $e->plan, 'features' => self::strings($e->features)];
    }

    /** @return list<string> */
    private static function strings(mixed $v): array
    {
        return is_array($v) ? array_values(array_filter($v, 'is_string')) : [];
    }
}
