<?php

declare(strict_types=1);

namespace Gatekeeper\Tests;

use Gatekeeper\AdminClient;
use PHPUnit\Framework\TestCase;

/** Runs against a real Gatekeeper started by tests/feature/sdk (ADR-0088); skipped without GK_LIVE_ISSUER. */
final class LiveAdminTest extends TestCase
{
    public function testListsTheTenantsClients(): void
    {
        $issuer = getenv('GK_LIVE_ISSUER');
        if ($issuer === false) {
            self::markTestSkipped('no live server (GK_LIVE_ISSUER)');
        }
        $api = AdminClient::make($issuer, (string) getenv('GK_LIVE_ADMIN_TOKEN'));
        $ids = array_map(static fn ($c) => $c->getClientId(), $api->adminListClients()->getItems());
        self::assertContains(getenv('GK_LIVE_CLIENT'), $ids);
    }
}
