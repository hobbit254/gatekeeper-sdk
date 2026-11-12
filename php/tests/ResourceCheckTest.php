<?php

declare(strict_types=1);

namespace Gatekeeper\Tests;

use Gatekeeper\Config;
use Gatekeeper\Gatekeeper;
use Gatekeeper\Laravel\GatekeeperAuthenticate;
use Gatekeeper\Laravel\RequirePermissionOn;
use Gatekeeper\Principal;
use Illuminate\Http\Request;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Response;

/** Resource checks through the server (FR-Z12, ADR-0108). */
final class ResourceCheckTest extends TestCase
{
    private int $calls = 0;

    private function sdk(): Gatekeeper
    {
        $decide = fn (string $r): array => match ($r) {
            'campaign:1' => ['allow' => true, 'matched_by' => 'relation:can_edit'],
            'campaign:2' => ['allow' => false, 'matched_by' => 'step_up_required', 'max_age' => 300],
            default => ['allow' => false, 'matched_by' => 'none'],
        };
        return new Gatekeeper(new Config('https://auth.test/t/acme', 'api', 'api', 's'), null,
            function (string $url, array $headers, ?string $body = null) use ($decide): array {
                $this->calls++;
                if (($headers['Authorization'] ?? '') !== 'Bearer tok') {
                    return [401, '{}'];
                }
                $b = json_decode((string) $body, true);
                if (str_ends_with($url, '/v1/authz/check')) {
                    return [200, json_encode($decide($b['resource']))];
                }
                return [200, json_encode(['results' => array_map(fn ($c) => $decide($c['resource']), $b['checks'])])];
            });
    }

    public function testAsksEveryTimeAndBatches(): void
    {
        $g = $this->sdk();
        self::assertSame(['allow' => true, 'matched_by' => 'relation:can_edit'], $g->canOn('tok', 'campaign:update', 'campaign:1'));
        $g->canOn('tok', 'campaign:update', 'campaign:1');
        self::assertSame(2, $this->calls);
        $each = $g->canOnEach('tok', 'campaign:update', ['campaign:1', 'campaign:3', 'campaign:2']);
        self::assertSame([true, false, false], array_column($each, 'allow'));
        $this->expectException(\RuntimeException::class);
        $g->canOn('wrong', 'campaign:update', 'campaign:1');
    }

    public function testMiddleware(): void
    {
        $mw = new RequirePermissionOn($this->sdk());
        $run = function (string $id, string $auth, bool $verified = true) use ($mw): Response {
            $req = Request::create('/campaigns/' . $id, 'POST');
            $req->headers->set('Authorization', $auth);
            $route = new class ($id) { // Request::route($name) only asks the route for a parameter
                public function __construct(private string $id)
                {
                }

                public function parameter(string $name, mixed $default = null): mixed
                {
                    return $name === 'campaign' ? $this->id : $default;
                }
            };
            $req->setRouteResolver(fn () => $route);
            if ($verified) {
                $req->attributes->set(GatekeeperAuthenticate::ATTRIBUTE, new Principal('u', 't', null, 'web', [], [], [], ['pwd'], 0, 0));
            }
            return $mw->handle($req, fn () => new Response('ok'), 'campaign', 'update', 'campaign');
        };
        self::assertSame(200, $run('1', 'Bearer tok')->getStatusCode());
        self::assertSame(403, $run('3', 'Bearer tok')->getStatusCode());
        $step = $run('2', 'Bearer tok');
        self::assertSame(401, $step->getStatusCode());
        self::assertSame('Bearer error="insufficient_user_authentication", max_age="300", acr_values="mfa"', $step->headers->get('WWW-Authenticate'));
        self::assertSame(403, $run('1', 'DPoP tok')->getStatusCode());
        self::assertSame(403, $run('1', 'Bearer tok', false)->getStatusCode());
        self::assertSame(503, $run('1', 'Bearer other')->getStatusCode());
    }
}
