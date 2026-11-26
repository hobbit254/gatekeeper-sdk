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
