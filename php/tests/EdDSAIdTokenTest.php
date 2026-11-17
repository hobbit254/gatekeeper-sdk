<?php

declare(strict_types=1);

namespace Gatekeeper\Tests;

use Firebase\JWT\JWT;
use Gatekeeper\Config;
use Gatekeeper\Gatekeeper;
use Gatekeeper\InvalidTokenException;
use Jose\Component\KeyManagement\JWKFactory;
use PHPUnit\Framework\TestCase;

/** FR-S19 (ADR-0124): EdDSA ID tokens verify; access tokens stay ES256; no borrowing the other ring's key. */
final class EdDSAIdTokenTest extends TestCase
{
    private const ISSUER = 'https://auth.test/t/acme';

    private string $ec = '';

    private string $edSecret = '';

    private string $edPublic = '';

    protected function setUp(): void
    {
        $k = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        openssl_pkey_export($k, $this->ec);
        $pair = sodium_crypto_sign_keypair();
        $this->edSecret = base64_encode(sodium_crypto_sign_secretkey($pair));
        $this->edPublic = sodium_crypto_sign_publickey($pair);
    }

    private function sdk(): Gatekeeper
    {
        $ec = JWKFactory::createFromKey($this->ec, null, ['kid' => 'ec', 'use' => 'sig', 'alg' => 'ES256'])->toPublic()->jsonSerialize();
        $ed = ['kty' => 'OKP', 'crv' => 'Ed25519', 'x' => JWT::urlsafeB64Encode($this->edPublic), 'kid' => 'ed', 'use' => 'sig', 'alg' => 'EdDSA'];
        $jwks = json_encode(['keys' => [$ec, $ed]]);
        return new Gatekeeper(new Config(self::ISSUER, 'api', 'web'), null,
            fn (string $url): array => $url === self::ISSUER . '/.well-known/jwks.json' ? [200, $jwks, []] : [404, '{}', []]);
    }

    /** @param array<string, mixed> $extra */
    private function token(string $alg, string $kid, string $aud = 'web', string $typ = 'JWT', array $extra = []): string
    {
        $key = $alg === 'EdDSA' ? $this->edSecret : $this->ec;
        return JWT::encode(['iss' => self::ISSUER, 'aud' => $aud, 'sub' => 'u1', 'nonce' => 'n', 'iat' => time(), 'exp' => time() + 300] + $extra,
            $key, $alg, $kid, ['typ' => $typ]);
    }

    public function testEdDSAAndES256IdTokensVerify(): void
    {
        self::assertSame('u1', $this->sdk()->verifyIdToken($this->token('EdDSA', 'ed'), 'n')['sub']);
        self::assertSame('u1', $this->sdk()->verifyIdToken($this->token('ES256', 'ec'))['sub']);
    }

    public function testEdDSAUnderTheEcKidIsRefused(): void
    {
        $this->expectException(InvalidTokenException::class);
        $this->sdk()->verifyIdToken($this->token('EdDSA', 'ec'));
    }

    public function testES256UnderTheEd25519KidIsRefused(): void
    {
        $this->expectException(InvalidTokenException::class);
        $this->sdk()->verifyIdToken($this->token('ES256', 'ed'));
    }

    public function testAnEdDSAAccessTokenIsRefused(): void
    {
        $this->expectException(InvalidTokenException::class);
        $this->sdk()->verify($this->token('EdDSA', 'ed', 'api', 'at+jwt', ['client_id' => 'web', 'jti' => 'j']));
    }
}
