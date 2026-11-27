<?php

declare(strict_types=1);

namespace Gatekeeper\Tests;

use Firebase\JWT\JWT;
use Gatekeeper\Config;
use Gatekeeper\Gatekeeper;
use Gatekeeper\Principal;
use Jose\Component\KeyManagement\JWKFactory;
use PHPUnit\Framework\TestCase;

/** FR-M5 (ADR-0146): read-mode support access keeps only read permissions; an act without mode is read. */
final class ActorModeTest extends TestCase
{
    private const ISSUER = 'https://auth.test/t/acme';

    private string $key = '';

    private bool $withRead = true;

    protected function setUp(): void
    {
        $k = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        openssl_pkey_export($k, $this->key);
    }

    /** @param array<string, mixed>|null $act */
    private function verify(?array $act): Principal
    {
        $jwk = JWKFactory::createFromKey($this->key, null, ['kid' => 'k1', 'use' => 'sig', 'alg' => 'ES256'])->toPublic()->jsonSerialize();
        $jwks = json_encode(['keys' => [$jwk]]);
        $map = ['rv' => 1, 'roles' => ['ops' => ['report:read', 'report:list', 'report:export']]];
        if ($this->withRead) {
            $map['read'] = ['report:read', 'report:list'];
        }
        $g = new Gatekeeper(new Config(self::ISSUER, 'api', 'web'), null, fn (string $url): array => match ($url) {
            self::ISSUER . '/.well-known/jwks.json' => [200, $jwks, []],
            self::ISSUER . '/v1/clients/web/role-map' => [200, json_encode($map), []],
            default => [404, '{}', []],
        });
        $claims = ['iss' => self::ISSUER, 'aud' => 'api', 'sub' => 'u1', 'client_id' => 'web', 'jti' => 'j', 'roles' => ['ops'], 'rv' => 1, 'exp' => time() + 60];
        if ($act !== null) {
            $claims['act'] = $act;
        }
        return $g->verify(JWT::encode($claims, $this->key, 'ES256', 'k1', ['typ' => 'at+jwt']));
    }

    public function testModes(): void
    {
        $this->assertNull($this->verify(null)->actorMode);
        $this->assertCount(3, $this->verify(null)->permissions);
        $read = $this->verify(['sub' => 'admin', 'mode' => 'read']);
        $this->assertSame(Principal::ACTOR_READ, $read->actorMode);
        $this->assertTrue($read->can('report:list'));
        $this->assertFalse($read->can('report:export'));
        $write = $this->verify(['sub' => 'admin', 'mode' => 'write']);
        $this->assertSame(Principal::ACTOR_WRITE, $write->actorMode);
        $this->assertTrue($write->can('report:export'));
        $this->assertFalse($this->verify(['sub' => 'admin'])->can('report:export'));
        $this->withRead = false;
        $this->assertSame(['report:read'], $this->verify(['sub' => 'admin', 'mode' => 'read'])->permissions);
    }
}
