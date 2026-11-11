<?php

declare(strict_types=1);

namespace Gatekeeper\Tests;

use Gatekeeper\Laravel\GatekeeperAuthenticate;
use Gatekeeper\Laravel\RequirePermission;
use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Response;

/** Per-permission step-up cases of the shared contract (ADR-0097). */
final class PermissionStepUpTest extends TestCase
{
    /** @return iterable<string, array{string, string, string, int}> */
    public static function cases(): iterable
    {
        foreach ((new Fixtures())->v['permission_step_up'] as $c) {
            yield $c['name'] => [$c['token'], $c['permission'], $c['expect'], $c['max_age'] ?? 0];
        }
    }

    #[DataProvider('cases')]
    public function testVector(string $token, string $permission, string $expect, int $maxAge): void
    {
        $req = Request::create('/');
        $req->attributes->set(GatekeeperAuthenticate::ATTRIBUTE, (new Fixtures())->sdk()->verify($token));
        $res = (new RequirePermission())->handle($req, fn () => new Response('ok'), ...explode(':', $permission));
        self::assertSame(['allow' => 200, 'deny' => 403, 'step_up' => 401][$expect], $res->getStatusCode());
        if ($expect === 'step_up') {
            self::assertSame(sprintf('Bearer error="insufficient_user_authentication", max_age="%d", acr_values="mfa"', $maxAge),
                $res->headers->get('WWW-Authenticate'));
        }
    }
}
