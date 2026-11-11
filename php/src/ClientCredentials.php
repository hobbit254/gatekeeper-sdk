<?php

declare(strict_types=1);

namespace Gatekeeper;

use Firebase\JWT\JWT;
use Psr\SimpleCache\CacheInterface;

/**
 * Fetches and caches an m2m access token (FR-M1, ADR-0059). The token is
 * reused until a minute before it expires; with Laravel's cache store every
 * worker shares it. withDPoPKey() binds the token to a P-256 key (FR-S12, ADR-0096).
 */
final class ClientCredentials
{
    private CacheInterface $cache;

    private ?\OpenSSLAsymmetricKey $dpopKey = null;

    /** @var array<string, string> the key's public JWK */
    private array $dpopJwk = [];

    /** The latest DPoP-Nonce from the token endpoint. */
    private string $nonce = '';

    /** @var callable(string, array<string, string>, ?string=): array{0: int, 1: string, 2?: array<string, string>} */
    private $fetch;

    /** @param ?callable(string, array<string, string>, ?string=): array{0: int, 1: string, 2?: array<string, string>} $fetch returns [status, body, lowercased response headers]; tests inject one */
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

    /** A copy that sends DPoP proofs signed by $pem, an EC P-256 private key (ES256). */
    public function withDPoPKey(string $pem): self
    {
        $key = openssl_pkey_get_private($pem);
        $ec = $key === false ? null : (openssl_pkey_get_details($key)['ec'] ?? null);
        if ($key === false || ($ec['curve_name'] ?? '') !== 'prime256v1') {
            throw new \InvalidArgumentException('gatekeeper: the DPoP key must be an EC P-256 private key');
        }
        $c = clone $this;
        $c->dpopKey = $key;
        $c->dpopJwk = ['kty' => 'EC', 'crv' => 'P-256',
            'x' => JWT::urlsafeB64Encode(str_pad($ec['x'], 32, "\0", STR_PAD_LEFT)),
            'y' => JWT::urlsafeB64Encode(str_pad($ec['y'], 32, "\0", STR_PAD_LEFT))];
        return $c;
    }

    /** A DPoP proof for an API call made with $token (RFC 9449 §4), carrying the latest nonce. */
    public function proof(string $method, string $url, string $token = ''): string
    {
        if ($this->dpopKey === null) {
            throw new \LogicException('gatekeeper: proof needs withDPoPKey()');
        }
        $u = parse_url($url);
        $claims = ['jti' => bin2hex(random_bytes(16)), 'htm' => strtoupper($method), 'iat' => time(),
            'htu' => ($u['scheme'] ?? '') . '://' . ($u['host'] ?? '') . (isset($u['port']) ? ':' . $u['port'] : '') . ($u['path'] ?? '')];
        if ($token !== '') {
            $claims['ath'] = JWT::urlsafeB64Encode(hash('sha256', $token, true));
        }
        if ($this->nonce !== '') {
            $claims['nonce'] = $this->nonce;
        }
        return JWT::encode($claims, $this->dpopKey, 'ES256', null, ['typ' => 'dpop+jwt', 'jwk' => $this->dpopJwk]);
    }

    /** Returns an access token valid for at least another minute. */
    public function token(): string
    {
        $key = 'gatekeeper.cc.' . hash('sha256', $this->tokenUrl . '|' . $this->clientId . '|' . $this->scope . '|' . $this->audience
            . '|' . ($this->dpopJwk['x'] ?? '')); // a bound token belongs to its key
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
        for ($attempt = 0; ; $attempt++) {
            if ($this->dpopKey !== null) {
                $headers['DPoP'] = $this->proof('POST', $this->tokenUrl);
            }
            $res = ($this->fetch)($this->tokenUrl, $headers, http_build_query($form));
            [$status, $body] = $res;
            $this->nonce = $res[2]['dpop-nonce'] ?? $this->nonce;
            $r = json_decode($body, true);
            if ($attempt === 0 && $this->dpopKey !== null && $status === 400 && ($r['error'] ?? '') === 'use_dpop_nonce') {
                continue; // RFC 9449 §8: retry once with the nonce just received
            }
            break;
        }
        if ($status !== 200 || !is_array($r) || !is_string($r['access_token'] ?? null)) {
            throw new \RuntimeException("gatekeeper: client credentials: status {$status}");
        }
        $ttl = max(1, (int) ($r['expires_in'] ?? 0) - 60);
        $this->cache->set($key, $r['access_token'], $ttl);
        return $r['access_token'];
    }
}
