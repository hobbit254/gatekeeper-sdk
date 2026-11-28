<?php

declare(strict_types=1);

namespace Gatekeeper\Laravel;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Marks a route as deliberately open, for GatekeeperAssert: Route::middleware('gk.public').
 * It changes nothing at run time (ADR-0149).
 */
final class MarkPublic
{
    public function handle(Request $request, Closure $next): Response
    {
        return $next($request);
    }
}
