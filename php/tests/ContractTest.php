<?php

declare(strict_types=1);

namespace Gatekeeper\Tests;

use Gatekeeper\InvalidTokenException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** The shared contract every SDK must pass (ADR-0038). */
final class ContractTest extends TestCase
{
    /** @return iterable<string, array{string, string, string}> */
    public static function cases(): iterable
    {
        foreach ((new Fixtures())->v['cases'] as $c) {
            yield $c['name'] => [$c['token'], $c['permission'], $c['expect']];
        }
    }

    /** @return iterable<string, array{string, string, string}> */
    public static function orgCases(): iterable
    {
        foreach ((new Fixtures())->v['org_roles']['cases'] as $c) {
            yield $c['name'] => [$c['token'], $c['permission'], $c['expect']];
        }
    }

    /** Organization roles resolve only through their own organization's map (ADR-0142). */
    #[DataProvider('orgCases')]
    public function testOrgRoleVector(string $token, string $permission, string $expect): void
    {
        $this->testVector($token, $permission, $expect);
    }

    /** @return iterable<string, array{string, string, int, string}> */
    public static function amountCases(): iterable
    {
        foreach ((new Fixtures())->v['amount_limits']['cases'] as $c) {
            yield $c['name'] => [$c['token'], $c['permission'], $c['amount'], $c['expect']];
        }
    }

    /** canAmount answers within, above or without the permission; in an organization, with its overrides (ADR-0143). */
    #[DataProvider('amountCases')]
    public function testAmountLimit(string $token, string $permission, int $amount, string $expect): void
    {
        $f = new Fixtures();
        $p = $f->sdk()->verify($token);
        self::assertSame($expect, $p->canAmount($permission, $amount));
        if ($p->limits !== []) {
            self::assertSame($f->v['amount_limits']['currency'][$p->orgId === 'acme' ? 'acme' : 'tenant'], $p->currency);
        }
    }

    #[DataProvider('cases')]
    public function testVector(string $token, string $permission, string $expect): void
    {
        try {
            $got = (new Fixtures())->sdk()->verify($token)->can($permission) ? 'allow' : 'deny';
        } catch (InvalidTokenException) {
            $got = 'reject';
        }
        self::assertSame($expect, $got);
    }
}
