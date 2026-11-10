<?php

declare(strict_types=1);

namespace Gatekeeper\Tests;

use Gatekeeper\InvalidTokenException;
use Gatekeeper\Laravel\GatekeeperAuthenticate;
use Illuminate\Http\Request;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Response;

/** DPoP (RFC 9449, ADR-0070) against the shared contract. */
final class DPoPTest extends TestCase
{
    public function testContractCasesInOrderWithOneReplayCache(): void
    {
        $f = new Fixtures();
        $sdk = $f->sdk();
        $d = $f->v['dpop'];
        $p = $sdk->verify($d['token']);
        self::assertSame($d['jkt'], $p->jkt);
        foreach ($d['cases'] as $c) {
            try {
                $sdk->verifyDPoP($p, $d['token'], $c['proof'], $d['method'], $d['url'], $d['now']);
                $got = 'allow';
            } catch (InvalidTokenException) {
                $got = 'reject';
            }
            self::assertSame($c['expect'], $got, $c['name']);
        }
    }

    public function testMiddlewareRefusesTheWrongScheme(): void
    {
        $f = new Fixtures();
        $mw = new GatekeeperAuthenticate($f->sdk());
        foreach (['Bearer ' . $f->v['dpop']['token'], 'DPoP ' . $f->v['dpop']['token'], 'DPoP ' . $f->v['impersonation']['plain']] as $auth) {
            $req = Request::create('https://api.example.test/orders', 'GET', server: ['HTTP_AUTHORIZATION' => $auth]);
            $res = $mw->handle($req, fn () => new Response('ok'));
            self::assertSame(401, $res->getStatusCode(), substr($auth, 0, 12));
        }
    }
}
