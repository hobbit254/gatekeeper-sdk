<?php

declare(strict_types=1);

namespace Gatekeeper\Tests;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Gatekeeper\ClientCredentials;
use PHPUnit\Framework\TestCase;

/** FR-S12 (ADR-0096): the client-credentials helper binds its token to a key. */
final class M2MDPoPTest extends TestCase
{
    private const URL = 'https://auth.test/t/acme/oauth2/token';

    /** @return array{array<string, mixed>, array<string, mixed>} verified claims and header */
    private static function proof(string $jwt): array
    {
        $header = json_decode(JWT::urlsafeB64Decode(explode('.', $jwt)[0]), true);
        self::assertSame('dpop+jwt', $header['typ']);
        self::assertArrayNotHasKey('d', $header['jwk']);
        return [(array) JWT::decode($jwt, JWK::parseKey($header['jwk'], 'ES256')), $header];
    }

    private static function pem(): string
    {
        openssl_pkey_export(openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']), $pem);
        return $pem;
    }

    public function testBindsTheTokenRetriesForTheNonceAndSignsAPICalls(): void
    {
        $seen = [];
        $fetch = function (string $url, array $headers, ?string $body = null) use (&$seen): array {
            [$claims] = self::proof($headers['DPoP'] ?? '');
            $seen[] = $claims;
            self::assertSame(['POST', self::URL], [$claims['htm'], $claims['htu']]);
            if (($claims['nonce'] ?? '') !== 'n-1') {
                return [400, '{"error":"use_dpop_nonce"}', ['dpop-nonce' => 'n-1']];
            }
            return [200, '{"access_token":"tok-1","token_type":"DPoP","expires_in":600}', ['dpop-nonce' => 'n-1']];
        };
        $cc = (new ClientCredentials(self::URL, 'batch', 's', fetch: $fetch))->withDPoPKey(self::pem());
        self::assertSame('tok-1', $cc->token());
        self::assertCount(2, $seen);

        [$claims] = self::proof($cc->proof('get', 'https://api.test:8443/v1/jobs?page=2', 'tok-1'));
        self::assertSame(['GET', 'https://api.test:8443/v1/jobs', 'n-1'], [$claims['htm'], $claims['htu'], $claims['nonce']]);
        self::assertSame(JWT::urlsafeB64Encode(hash('sha256', 'tok-1', true)), $claims['ath']);
    }

    public function testGivesUpAfterOneRetry(): void
    {
        $calls = 0;
        $fetch = function () use (&$calls): array {
            $calls++;
            return [400, '{"error":"use_dpop_nonce"}', ['dpop-nonce' => "n-{$calls}"]];
        };
        $cc = (new ClientCredentials(self::URL, 'batch', 's', fetch: $fetch))->withDPoPKey(self::pem());
        try {
            $cc->token();
            self::fail('want an error');
        } catch (\RuntimeException) {
            self::assertSame(2, $calls);
        }
    }

    public function testRefusesOtherKeysAndProofsWithoutOne(): void
    {
        openssl_pkey_export(openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]), $rsa);
        try {
            (new ClientCredentials(self::URL, 'batch', 's'))->withDPoPKey($rsa);
            self::fail('RSA must be refused');
        } catch (\InvalidArgumentException) {
        }
        $this->expectException(\LogicException::class);
        (new ClientCredentials(self::URL, 'batch', 's'))->proof('GET', 'https://api.test/', 't');
    }
}
