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
        self::assertSame(503, $run('1', 'DPoP tok')->getStatusCode(), 'with a secret it checks on behalf; this fake refuses the credentials');
        self::assertSame(403, $run('1', 'Bearer tok', false)->getStatusCode());
        self::assertSame(503, $run('1', 'Bearer other')->getStatusCode());
    }

    /** Checks on behalf of a user with the client's credentials (FR-Z16, ADR-0119). */
    private function onBehalf(string $secret, int &$tokens): Gatekeeper
    {
        return new Gatekeeper(new Config('https://auth.test/t/acme', 'api', 'shop', $secret), null,
            function (string $url, array $headers, ?string $body = null) use (&$tokens): array {
                if (str_ends_with($url, '/oauth2/token')) {
                    $tokens++;
                    parse_str((string) $body, $form);
                    $ok = ($headers['Authorization'] ?? '') === 'Basic ' . base64_encode('shop:s3cret') && ($form['scope'] ?? '') === 'authz:check';
                    return $ok ? [200, json_encode(['access_token' => 'cc', 'expires_in' => 300])] : [401, '{}'];
                }
                if (($headers['Authorization'] ?? '') !== 'Bearer cc') {
                    return [401, '{}'];
                }
                $b = json_decode((string) $body, true);
                if (($b['user_id'] ?? '') !== 'u-1') {
                    return [403, json_encode(['type' => 'https://gatekeeper.dev/problems/user-not-served'])];
                }
                if (str_ends_with($url, '/v1/authz/check')) {
                    return [200, json_encode(['allow' => $b['resource'] === 'campaign:1', 'matched_by' => 'relation:can_edit'])];
                }
                return [200, json_encode(['results' => array_map(fn ($c) => ['allow' => $c['resource'] === 'campaign:1', 'matched_by' => 'none'], $b['checks'])])];
            });
    }

    public function testChecksOnBehalfWithTheClientsToken(): void
    {
        $tokens = 0;
        $g = $this->onBehalf('s3cret', $tokens);
        self::assertTrue($g->canOnFor('u-1', 'campaign:update', 'campaign:1')['allow']);
        self::assertSame([true, false], array_column($g->canOnEachFor('u-1', 'campaign:update', ['campaign:1', 'campaign:2']), 'allow'));
        self::assertSame(1, $tokens, 'the client token is cached');
        $this->expectException(\Gatekeeper\NotServedException::class);
        $g->canOnFor('u-2', 'campaign:update', 'campaign:1');
    }

    public function testMiddlewareChecksDPoPBoundUsersOnBehalf(): void
    {
        $tokens = 0;
        $run = function (Gatekeeper $g, string $sub): int {
            $req = Request::create('/campaigns/1', 'POST');
            $req->headers->set('Authorization', 'DPoP tok');
            $route = new class () {
                public function parameter(string $name, mixed $default = null): mixed
                {
                    return $name === 'campaign' ? '1' : $default;
                }
            };
            $req->setRouteResolver(fn () => $route);
            $req->attributes->set(GatekeeperAuthenticate::ATTRIBUTE, new Principal($sub, 't', null, 'web', [], [], [], ['pwd'], 0, 0, jkt: 'thumb'));
            return (new RequirePermissionOn($g))->handle($req, fn () => new Response('ok'), 'campaign', 'update', 'campaign')->getStatusCode();
        };
        self::assertSame(200, $run($this->onBehalf('s3cret', $tokens), 'u-1'));
        self::assertSame(403, $run($this->onBehalf('s3cret', $tokens), 'u-2'), 'not served');
        self::assertSame(403, $run($this->onBehalf('', $tokens), 'u-1'), 'no secret: refused, as before');
    }
}
