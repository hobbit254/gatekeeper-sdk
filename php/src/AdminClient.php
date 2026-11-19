<?php

declare(strict_types=1);

namespace Gatekeeper;

use Gatekeeper\Admin\Api\DefaultApi;
use Gatekeeper\Admin\Configuration;
use GuzzleHttp\Client;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use Psr\Http\Message\RequestInterface;

/**
 * Typed admin API client (FR-D13, ADR-0088). The code under admin/lib is
 * generated from sdk/admin-openapi.json: regenerate with `make sdk-clients`.
 */
final class AdminClient
{
    /**
     * @param string                 $issuer The tenant issuer, e.g. https://auth.example.com/t/acme
     * @param string|callable():string $token A tenant admin's own access token (scope tenant:admin, a second
     *                                        factor within 10 minutes), or a callable returning it per request
     */
    public static function make(string $issuer, string|callable $token, ?HandlerStack $stack = null): DefaultApi
    {
        $stack ??= HandlerStack::create();
        $stack->push(Middleware::mapRequest(
            static fn (RequestInterface $r) => $r->withHeader('Authorization', 'Bearer ' . (is_string($token) ? $token : $token())),
        ), 'gatekeeper_bearer');
        $config = (new Configuration())->setHost(rtrim($issuer, '/'));
        return new DefaultApi(new Client(['handler' => $stack]), $config);
    }
}
