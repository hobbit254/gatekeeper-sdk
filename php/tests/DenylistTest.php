<?php

declare(strict_types=1);

namespace Gatekeeper\Tests;

use Gatekeeper\DenylistChecker;
use Gatekeeper\InvalidTokenException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** Denylist cases of the shared contract (ADR-0048). */
final class DenylistTest extends TestCase
{
    /** @return iterable<string, array{string, string, string}> */
    public static function cases(): iterable
    {
        foreach ((new Fixtures())->v['denylist']['cases'] as $c) {
            yield $c['name'] => [$c['token'], $c['permission'], $c['expect']];
        }
    }

    #[DataProvider('cases')]
    public function testVector(string $token, string $permission, string $expect): void
    {
        $f = new Fixtures();
        $set = new class ($f->v['denylist']['sids'], $f->v['denylist']['jtis']) implements DenylistChecker {
            /** @param list<string> $sids @param list<string> $jtis */
            public function __construct(private array $sids, private array $jtis)
            {
            }

            public function denied(string $sid, string $jti): bool
            {
                return in_array($sid, $this->sids, true) || in_array($jti, $this->jtis, true);
            }
        };
        try {
            $got = $f->sdk($set)->verify($token)->can($permission) ? 'allow' : 'deny';
        } catch (InvalidTokenException) {
            $got = 'reject';
        }
        self::assertSame($expect, $got);
    }

    public function testUnreachableDenylistRefuses(): void
    {
        $f = new Fixtures();
        $broken = new class () implements DenylistChecker {
            public function denied(string $sid, string $jti): bool
            {
                throw new \RuntimeException('redis down');
            }
        };
        $this->expectException(InvalidTokenException::class);
        $f->sdk($broken)->verify($f->v['denylist']['cases'][0]['token']);
    }
}
