<?php

declare(strict_types=1);

namespace Gatekeeper\Tests;

use PHPUnit\Framework\TestCase;

/** Entitlements from the token (ADR-0098). */
final class EntitlementsTest extends TestCase
{
    public function testThePlanAndFeaturesComeFromTheToken(): void
    {
        $f = new Fixtures();
        $e = $f->v['entitlements'];
        $p = $f->sdk()->verify($e['token']);
        self::assertSame(['plan' => $e['plan'], 'features' => $e['features']], $p->entitlements);
        foreach ($e['has'] as $feature) {
            self::assertTrue($p->hasFeature($feature), $feature);
        }
        foreach ($e['lacks'] as $feature) {
            self::assertFalse($p->hasFeature($feature), $feature);
        }
    }

    public function testATokenWithoutTheClaimHasNone(): void
    {
        $f = new Fixtures();
        $p = $f->sdk()->verify($f->v['entitlements']['plain']);
        self::assertNull($p->entitlements);
        self::assertFalse($p->hasFeature($f->v['entitlements']['has'][0]));
    }
}
