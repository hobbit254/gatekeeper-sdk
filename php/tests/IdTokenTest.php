<?php

declare(strict_types=1);

namespace Gatekeeper\Tests;

use Firebase\JWT\JWT;
use Gatekeeper\Config;
use Gatekeeper\Gatekeeper;
use Gatekeeper\InvalidTokenException;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A256GCM;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHESA256KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\RSAOAEP256;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Encryption\Serializer\CompactSerializer;
use Jose\Component\KeyManagement\JWKFactory;
use PHPUnit\Framework\TestCase;

/** ID tokens and userinfo, plain or encrypted to the client (FR-S15, ADR-0121). */
final class IdTokenTest extends TestCase
{
    private const ISSUER = 'https://auth.test/t/acme';

    private string $signing = '';
    private string $client = '';
    private string $clientPublic;

    protected function setUp(): void
    {
        $sig = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        openssl_pkey_export($sig, $this->signing);
        $enc = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
        openssl_pkey_export($enc, $this->client);
        $this->clientPublic = openssl_pkey_get_details($enc)['key'];
    }

    private function jwks(): string
    {
        $jwk = JWKFactory::createFromKey($this->signing, null, ['kid' => 'k1', 'use' => 'sig', 'alg' => 'ES256'])->toPublic();
        return json_encode(['keys' => [$jwk->jsonSerialize()]]);
    }

    private function sdk(string $decryptionKey, string $userinfoBody = '', string $userinfoType = 'application/json'): Gatekeeper
    {
        return new Gatekeeper(new Config(self::ISSUER, 'api', 'web', decryptionKey: $decryptionKey), null,
            function (string $url) use ($userinfoBody, $userinfoType): array {
                return match ($url) {
                    self::ISSUER . '/.well-known/jwks.json' => [200, $this->jwks(), []],
                    self::ISSUER . '/oauth2/userinfo' => [200, $userinfoBody, ['content-type' => $userinfoType]],
                    default => [404, '{}', []],
                };
            });
    }

    private function idToken(string $aud = 'web'): string
    {
        return JWT::encode(['iss' => self::ISSUER, 'aud' => $aud, 'sub' => 'u1', 'nonce' => 'n-1', 'name' => 'Wanjiku',
            'iat' => time(), 'exp' => time() + 300], $this->signing, 'ES256', 'k1', ['typ' => 'JWT']);
    }

    private function seal(string $jws): string
    {
        $jwe = (new JWEBuilder(new AlgorithmManager([new RSAOAEP256(), new A256GCM()])))->create()->withPayload($jws)
            ->withSharedProtectedHeader(['alg' => 'RSA-OAEP-256', 'enc' => 'A256GCM', 'cty' => 'JWT'])
            ->addRecipient(JWKFactory::createFromKey($this->clientPublic))->build();
        return (new CompactSerializer())->serialize($jwe, 0);
    }

    public function testDecryptsThenVerifies(): void
    {
        $g = $this->sdk($this->client);
        self::assertSame('Wanjiku', $g->verifyIdToken($this->seal($this->idToken()), 'n-1')['name']);
        self::assertSame('u1', $g->verifyIdToken($this->idToken())['sub'], 'plain still works');
    }

    public function testRefusesTheWrongNonceAudienceOrKey(): void
    {
        foreach ([
            fn () => $this->sdk($this->client)->verifyIdToken($this->seal($this->idToken()), 'n-2'),
            fn () => $this->sdk($this->client)->verifyIdToken($this->seal($this->idToken('other'))),
            fn () => $this->sdk('')->verifyIdToken($this->seal($this->idToken())),
            function () {
                $other = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
                openssl_pkey_export($other, $pem);
                $this->sdk($pem)->verifyIdToken($this->seal($this->idToken()));
            },
        ] as $i => $call) {
            try {
                $call();
                self::fail("case {$i} should be refused");
            } catch (InvalidTokenException) {
                $this->addToAssertionCount(1);
            }
        }
    }

    public function testOpensECDHToo(): void
    {
        $ec = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        openssl_pkey_export($ec, $pem);
        $jwe = (new JWEBuilder(new AlgorithmManager([new ECDHESA256KW(), new A256GCM()])))->create()->withPayload($this->idToken())
            ->withSharedProtectedHeader(['alg' => 'ECDH-ES+A256KW', 'enc' => 'A256GCM', 'cty' => 'JWT'])
            ->addRecipient(JWKFactory::createFromKey(openssl_pkey_get_details($ec)['key']))->build();
        self::assertSame('Wanjiku', $this->sdk($pem)->verifyIdToken((new CompactSerializer())->serialize($jwe, 0), 'n-1')['name']);
    }

    public function testUserInfoOpensAnEncryptedAnswer(): void
    {
        $g = $this->sdk($this->client, $this->seal($this->idToken()), 'application/jwt');
        self::assertSame('Wanjiku', $g->userInfo('at')['name']);
        self::assertSame(['sub' => 'u1'], $this->sdk('', '{"sub":"u1"}')->userInfo('at'));
    }
}
