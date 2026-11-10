<?php

declare(strict_types=1);

namespace Gatekeeper\Tests;

use Gatekeeper\Laravel\RequireStepUp;
use Gatekeeper\Laravel\GatekeeperAuthenticate;
use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Response;

/** Step-up cases of the shared contract (ADR-0046). */
final class StepUpTest extends TestCase
{
    /** @return iterable<string, array{string, int, bool}> */
    public static function cases(): iterable
    {
        foreach ((new Fixtures())->v['step_up'] as $c) {
            yield $c['name'] => [$c['token'], $c['max_age'], $c['fresh']];
        }
    }

    #[DataProvider('cases')]
    public function testVector(string $token, int $maxAge, bool $fresh): void
    {
        $req = Request::create('/');
        $req->attributes->set(GatekeeperAuthenticate::ATTRIBUTE, (new Fixtures())->sdk()->verify($token));
        $res = (new RequireStepUp())->handle($req, fn () => new Response('ok'), (string) $maxAge);
        self::assertSame($fresh ? 200 : 401, $res->getStatusCode());
        if (!$fresh) {
            self::assertSame(sprintf('Bearer error="insufficient_user_authentication", max_age="%d"', $maxAge),
                $res->headers->get('WWW-Authenticate'));
        }
    }
}
