<?php

declare(strict_types=1);

namespace Gatekeeper\Laravel;

use Closure;
use Gatekeeper\Principal;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Answers 401 with the RFC 9470 challenge unless the principal has a second
 * factor ("mfa" in amr) within the given seconds: Route::middleware('gk.stepup:600') (ADR-0046).
 */
final class RequireStepUp
{
    public function handle(Request $request, Closure $next, string $maxAgeSec = '600'): Response
    {
        $maxAge = (int) $maxAgeSec;
        $p = GatekeeperAuthenticate::principal($request);
        if ($p === null || !self::fresh($p, $maxAge)) {
            return new Response('step-up required', 401, [
                'WWW-Authenticate' => sprintf('Bearer error="insufficient_user_authentication", max_age="%d"', $maxAge),
            ]);
        }
        return $next($request);
    }

    /** Whether $p signed in with a second factor within $maxAge seconds. */
    public static function fresh(Principal $p, int $maxAge): bool
    {
        return in_array('mfa', $p->amr, true) && time() - $p->authTime <= $maxAge;
    }
}
