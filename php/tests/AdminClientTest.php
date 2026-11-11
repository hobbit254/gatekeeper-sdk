<?php

declare(strict_types=1);

namespace Gatekeeper\Tests;

use Gatekeeper\AdminClient;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;

final class AdminClientTest extends TestCase
{
    public function testCallsTheTenantIssuerWithTheBearer(): void
    {
        $mock = new MockHandler([new Response(200, ['Content-Type' => 'application/json'], '{"items":[]}')]);
        $api = AdminClient::make('https://auth.test/t/acme/', static fn () => 'tok', HandlerStack::create($mock));
        $api->adminListClients();
        $req = $mock->getLastRequest();
        self::assertSame('https://auth.test/t/acme/v1/admin/clients', (string) $req->getUri()->withQuery(''));
        self::assertSame('Bearer tok', $req->getHeaderLine('Authorization'));
    }
}
