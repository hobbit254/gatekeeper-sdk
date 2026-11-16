<?php

declare(strict_types=1);

namespace Gatekeeper\Laravel;

use Closure;
use Gatekeeper\Gatekeeper;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Guards a route with a resource check (FR-Z12, ADR-0108):
 * Route::middleware('gk.can_on:campaign:update,campaign') checks campaign:update
 * on "campaign:<the {campaign} route parameter>". After 'gatekeeper'. Answers
 * 403 when denied, 401 with the step-up challenge when a fresher second factor
 * would allow it, 503 when Gatekeeper can't answer. A DPoP-bound token can't
 * be forwarded without its holder's proof, so for one it checks with the
 * client's credentials (canOnFor, ADR-0119); without a client secret it is 403.
 */
final class RequirePermissionOn
{
    public function __construct(private readonly Gatekeeper $gatekeeper)
    {
    }

    public function handle(Request $request, Closure $next, string ...$args): Response
    {
        $param = array_pop($args);
        $permission = implode(':', $args); // Laravel may split the permission on ':' too
        $token = str_starts_with((string) $request->header('Authorization', ''), 'Bearer ') ? (string) $request->bearerToken() : '';
        $id = $request->route($param);
        $p = GatekeeperAuthenticate::principal($request);
        if ($p === null || !is_scalar($id) || (string) $id === '') {
            return new Response('forbidden', 403);
        }
        $onBehalf = $token === '' || $p->jkt !== ''; // DPoP-bound: the client checks for the user (ADR-0119)
        if ($onBehalf && !$this->gatekeeper->checksOnBehalf()) {
            return new Response('forbidden', 403);
        }
        try {
            $d = $onBehalf ? $this->gatekeeper->canOnFor($p->sub, $permission, $param . ':' . $id)
                : $this->gatekeeper->canOn($token, $permission, $param . ':' . $id);
        } catch (\Gatekeeper\NotServedException) {
            return new Response('forbidden', 403);
        } catch (\RuntimeException) {
            return new Response('authorization unavailable', 503);
        }
        if ($d['allow'] ?? false) {
            return $next($request);
        }
        if (($d['max_age'] ?? 0) > 0) {
            return new Response('step-up required', 401, ['WWW-Authenticate' =>
                sprintf('Bearer error="insufficient_user_authentication", max_age="%d", acr_values="mfa"', $d['max_age'])]);
        }
        return new Response('forbidden', 403);
    }
}
