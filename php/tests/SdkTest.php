<?php

declare(strict_types=1);

namespace Gatekeeper\Tests;

use Firebase\JWT\JWT;
use Gatekeeper\Laravel\GatekeeperAuthenticate;
use Gatekeeper\Laravel\RequirePermission;
use Illuminate\Http\Request;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Response;

final class SdkTest extends TestCase
{
    public function testRoleMapIsCachedUntilATokenCarriesANewerRv(): void
    {
        $f = new Fixtures();
        $stale = ['client_id' => $f->v['client_id'], 'rv' => 2, 'roles' => ['viewer' => []]];
        $f = new Fixtures([$stale, $f->v['role_map']]);
        $sdk = $f->sdk();
        $viewer = $f->token('viewer may read');
        self::assertFalse($sdk->verify($viewer)->can('subscriber:read'), 'first fetch is the stale rv 2 map');
        self::assertTrue($sdk->verify($viewer)->can('subscriber:read'), 'token rv 3 > 2: refetched');
        $sdk->verify($viewer);
        self::assertSame(2, $f->roleMapFetches, 'no fetch while rv is current');
    }

    public function testAnOrganizationsMapIsCachedUntilATokenCarriesANewerOrv(): void
    {
        $f = new Fixtures();
        $acme = $f->v['org_roles']['role_maps']['acme'];
        $f = new Fixtures(null, ['acme' => [['rv' => 3, 'orv' => 1, 'org' => 'acme', 'roles' => []], $acme]]);
        $sdk = $f->sdk();
        $token = $f->v['org_roles']['cases'][0]['token']; // org acme, orv 2
        self::assertFalse($sdk->verify($token)->can('invoice:read'), 'first fetch is the stale orv 1 map');
        $p = $sdk->verify($token);
        self::assertTrue($p->can('invoice:read'), 'token orv 2 > 1: refetched');
        self::assertSame(2, $p->orv);
        $sdk->verify($token);
        self::assertSame(2, $f->orgMapFetches, 'no fetch while orv is current');
        self::assertSame(0, $f->roleMapFetches, "the tenant's map isn't needed");
    }

    public function testLeewayIsRestored(): void
    {
        JWT::$leeway = 7;
        $f = new Fixtures();
        $f->sdk()->verify($f->token('viewer may read'));
        self::assertSame(7, JWT::$leeway);
        JWT::$leeway = 0;
    }

    public function testMiddlewareRejectsMissingAndInvalidTokens(): void
    {
        $mw = new GatekeeperAuthenticate((new Fixtures())->sdk());
        $next = fn () => self::fail('must not pass');

        $res = $mw->handle(Request::create('/'), $next);
        self::assertSame(401, $res->getStatusCode());
        self::assertSame('Bearer', $res->headers->get('WWW-Authenticate'));

        $req = Request::create('/', server: ['HTTP_AUTHORIZATION' => 'Bearer not.a.jwt']);
        $res = $mw->handle($req, $next);
        self::assertSame(401, $res->getStatusCode());
        self::assertSame('Bearer error="invalid_token"', $res->headers->get('WWW-Authenticate'));
    }

    public function testMiddlewareStoresThePrincipalAndGuardChecksPermissions(): void
    {
        $f = new Fixtures();
        $req = Request::create('/', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $f->token('viewer may read')]);
        $ok = fn () => new Response('ok');
        $res = (new GatekeeperAuthenticate($f->sdk()))->handle($req, $ok);
        self::assertSame(200, $res->getStatusCode());
        $p = GatekeeperAuthenticate::principal($req);
        self::assertNotNull($p);
        self::assertSame(['viewer'], $p->roles);

        $guard = new RequirePermission();
        // Laravel passes 'gk.can:subscriber:read' as the parameters 'subscriber', 'read'.
        self::assertSame(200, $guard->handle($req, $ok, 'subscriber', 'read')->getStatusCode());
        self::assertSame(403, $guard->handle($req, $ok, 'subscriber', 'delete')->getStatusCode());
        self::assertSame(403, $guard->handle(Request::create('/'), $ok, 'subscriber:read')->getStatusCode());
    }
}
