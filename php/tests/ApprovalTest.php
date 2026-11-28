<?php

declare(strict_types=1);

namespace Gatekeeper\Tests;

use Firebase\JWT\JWT;
use Gatekeeper\ApprovalException;
use Gatekeeper\Config;
use Gatekeeper\Gatekeeper;
use Gatekeeper\Principal;
use Jose\Component\KeyManagement\JWKFactory;
use PHPUnit\Framework\TestCase;

/** FR-Z21 (ADR-0145): an approval verifies only for its requester and client; spending maps 409 and 422. */
final class ApprovalTest extends TestCase
{
    private const ISSUER = 'https://auth.test/t/acme';

    private string $key = '';

    private string $other = '';

    private int $spendStatus = 200;

    /** @var array<string, mixed> */
    private array $spent = [];

    protected function setUp(): void
    {
        foreach (['key', 'other'] as $name) {
            $k = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
            openssl_pkey_export($k, $this->{$name});
        }
    }

    private function sdk(): Gatekeeper
    {
        $jwk = JWKFactory::createFromKey($this->key, null, ['kid' => 'k1', 'use' => 'sig', 'alg' => 'ES256'])->toPublic()->jsonSerialize();
        $jwks = json_encode(['keys' => [$jwk]]);
        return new Gatekeeper(new Config(self::ISSUER, 'api', 'pos-api'), null, function (string $url, array $headers, ?string $body = null) use ($jwks): array {
            if ($url === self::ISSUER . '/.well-known/jwks.json') {
                return [200, $jwks, []];
            }
            if ($url === self::ISSUER . '/v1/approvals/spend') {
                $this->assertSame('Bearer at', $headers['Authorization']);
                $this->spent = json_decode((string) $body, true);
                return [$this->spendStatus, json_encode(['approval_id' => 'a1', 'status' => 'spent', 'approver_id' => 'boss', 'amount' => 300000]), []];
            }
            return [404, '{}', []];
        });
    }

    /** @param array<string, mixed> $edit */
    private function sign(array $edit = [], string $typ = 'approval+jwt', ?string $key = null): string
    {
        $now = time();
        $claims = array_merge(['iss' => self::ISSUER, 'aud' => 'pos', 'jti' => 'a1', 'sub' => 'boss', 'req' => 'cashier', 'perm' => 'sale:refund',
            'res' => 'sale:42', 'amt' => 300000, 'cur' => 'KES', 'method' => 'pin', 'iat' => $now, 'exp' => $now + 120], $edit);
        return JWT::encode($claims, $key ?? $this->key, 'ES256', 'k1', ['typ' => $typ]);
    }

    private function principal(): Principal
    {
        return new Principal('cashier', 't', null, 'pos', [], [], [], ['pin', 'hwk'], 0, 0);
    }

    public function testVerifiesOnlyItsOwnRequest(): void
    {
        $g = $this->sdk();
        $a = $g->verifyApproval($this->sign(), $this->principal());
        $this->assertSame('boss', $a->approver);
        $this->assertSame(300000, $a->amount);
        $this->assertSame('sale:refund', $a->permission);
        $bad = [
            'another typ' => $this->sign([], 'at+jwt'),
            'another key' => $this->sign([], 'approval+jwt', $this->other),
            'another issuer' => $this->sign(['iss' => 'https://evil.test']),
            'another client' => $this->sign(['aud' => 'web']),
            'another requester' => $this->sign(['req' => 'someone']),
        ];
        foreach ($bad as $name => $raw) {
            try {
                $g->verifyApproval($raw, $this->principal());
                $this->fail($name);
            } catch (ApprovalException $e) {
                $this->assertSame('mismatch', $e->reason, $name);
            }
        }
        try {
            $g->verifyApproval($this->sign(['exp' => time() - 300]), $this->principal());
            $this->fail('expired');
        } catch (ApprovalException $e) {
            $this->assertSame('closed', $e->reason);
        }
    }

    public function testSpendsOnce(): void
    {
        $g = $this->sdk();
        $a = $g->spendApproval('at', 'tok', 'sale:refund', 'sale:42', 300000);
        $this->assertSame('a1', $a->id);
        $this->assertSame(['token' => 'tok', 'permission' => 'sale:refund', 'resource' => 'sale:42', 'amount' => 300000], $this->spent);
        $g->spendApproval('at', 'tok', 'sale:void', 'sale:42');
        $this->assertArrayNotHasKey('amount', $this->spent);
        foreach ([409 => 'closed', 422 => 'mismatch'] as $status => $reason) {
            $this->spendStatus = $status;
            try {
                $g->spendApproval('at', 'tok', 'sale:refund', 'sale:42', 300000);
                $this->fail("status {$status}");
            } catch (ApprovalException $e) {
                $this->assertSame($reason, $e->reason);
            }
        }
        $this->spendStatus = 502;
        $this->expectException(\RuntimeException::class);
        $g->spendApproval('at', 'tok', 'sale:refund', 'sale:42', 300000);
    }
}
