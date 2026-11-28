<?php

declare(strict_types=1);

namespace Gatekeeper\Laravel;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Marks a route that any valid token may call, after the gatekeeper middleware, and
 * answers 401 without its Principal: Route::middleware(['gatekeeper', 'gk.signed_in']) (ADR-0149).
 */
final class RequireSignedIn
{
    public function handle(Request $request, Closure $next): Response
    {
        if (GatekeeperAuthenticate::principal($request) === null) {
            return new Response('unauthorized', 401, ['WWW-Authenticate' => 'Bearer']);
        }
        return $next($request);
    }
}
