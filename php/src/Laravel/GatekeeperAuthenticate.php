<?php

declare(strict_types=1);

namespace Gatekeeper\Laravel;

use Closure;
use Gatekeeper\Gatekeeper;
use Gatekeeper\InvalidTokenException;
use Gatekeeper\Principal;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Verifies the bearer token and stores the Principal on the request.
 * Failures are 401 with WWW-Authenticate: Bearer error="invalid_token" (TOKENS.md).
 */
final class GatekeeperAuthenticate
{
    public const ATTRIBUTE = 'gatekeeper.principal';

    public function __construct(private readonly Gatekeeper $gatekeeper)
    {
    }

    public function handle(Request $request, Closure $next): Response
    {
        $token = $request->bearerToken();
        if ($token === null || $token === '') {
            return new Response('unauthorized', 401, ['WWW-Authenticate' => 'Bearer']);
        }
        try {
            $principal = $this->gatekeeper->verify($token);
        } catch (InvalidTokenException) {
            return new Response('unauthorized', 401, ['WWW-Authenticate' => 'Bearer error="invalid_token"']);
        }
        $request->attributes->set(self::ATTRIBUTE, $principal);
        return $next($request);
    }

    /** The Principal this middleware stored, if any. */
    public static function principal(Request $request): ?Principal
    {
        $p = $request->attributes->get(self::ATTRIBUTE);
        return $p instanceof Principal ? $p : null;
    }
}
