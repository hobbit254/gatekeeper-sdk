<?php

declare(strict_types=1);

namespace Gatekeeper\Tests;

use Gatekeeper\GatekeeperAssert;
use Gatekeeper\Laravel\RequirePermission;
use Gatekeeper\UnguardedRoutesException;
use PHPUnit\Framework\TestCase;

/** FR-S20 (ADR-0149): routes without a guard are listed from their middleware, never run. */
final class GatekeeperAssertTest extends TestCase
{
    /** @param list<string> $middleware */
    private static function route(array $methods, string $uri, array $middleware): object
    {
        return new class ($methods, $uri, $middleware) {
            /** @param list<string> $m @param list<string> $mw */
            public function __construct(private array $m, private string $u, private array $mw)
            {
            }

            /** @return list<string> */
            public function methods(): array
            {
                return $this->m;
            }

            public function uri(): string
            {
                return $this->u;
            }

            /** @return list<string> */
            public function gatherMiddleware(): array
            {
                return $this->mw;
            }
        };
    }

    public function testListsUnguardedRoutesAndUnusedPermissions(): void
    {
        $routes = [
            self::route(['GET', 'HEAD'], 'orders', ['gatekeeper', 'gk.can:order,read']),
            self::route(['POST'], 'orders/{id}/refund', ['gatekeeper', 'gk.can_on:order,refund,id']),
            self::route(['GET', 'HEAD'], 'up', ['gk.public']),
            self::route(['GET', 'HEAD'], 'me', ['gatekeeper', 'gk.signed_in']),
            self::route(['DELETE'], 'account', ['gatekeeper', RequirePermission::class . ':account,delete']),
            self::route(['POST'], 'orders', ['gatekeeper']),
        ];
        $r = GatekeeperAssert::check($routes, ['order:read', 'order:export', 'account:delete']);
        $this->assertSame(['POST /orders'], $r['unguarded']);
        $this->assertSame(['order:export'], $r['unused']);

        try {
            GatekeeperAssert::everyRouteGuarded($routes);
            $this->fail('an unguarded route');
        } catch (UnguardedRoutesException $e) {
            $this->assertSame(['POST /orders'], $e->unguarded);
            $this->assertStringContainsString('POST /orders', $e->getMessage());
        }
        $this->assertSame([], GatekeeperAssert::everyRouteGuarded($routes, ignore: ['POST /orders'])['unguarded']);
        $this->expectException(UnguardedRoutesException::class);
        GatekeeperAssert::everyRouteGuarded($routes, ['order:export'], true, ['/orders']);
    }
}
