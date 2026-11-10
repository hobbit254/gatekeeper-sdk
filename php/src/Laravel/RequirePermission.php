<?php

declare(strict_types=1);

namespace Gatekeeper\Laravel;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Answers 403 unless the Principal holds the permission: Route::middleware('gk.can:campaign:publish').
 * Sensitive permissions and direct grants need /v1/authz/check (ADR-0005).
 */
final class RequirePermission
{
    public function handle(Request $request, Closure $next, string ...$permission): Response
    {
        $key = implode(':', $permission); // Laravel splits middleware parameters on ':' too
        $p = GatekeeperAuthenticate::principal($request);
        if ($p === null || !$p->can($key)) {
            return new Response('forbidden', 403);
        }
        return $next($request);
    }
}
