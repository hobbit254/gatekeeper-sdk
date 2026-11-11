<?php

declare(strict_types=1);

namespace Gatekeeper\Laravel;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Answers 403 unless the Principal holds the permission: Route::middleware('gk.can:campaign:publish').
 * A permission with its own step-up window answers 401 with the RFC 9470 challenge when
 * the user's second factor is older than that window (ADR-0097).
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
        $window = $p->stepUp[$key] ?? 0;
        if ($window > 0 && !$p->machine() && !RequireStepUp::fresh($p, $window)) {
            return new Response('step-up required', 401, [
                'WWW-Authenticate' => sprintf('Bearer error="insufficient_user_authentication", max_age="%d", acr_values="mfa"', $window),
            ]);
        }
        return $next($request);
    }
}
