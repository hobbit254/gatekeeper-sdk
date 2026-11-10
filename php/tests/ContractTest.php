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
