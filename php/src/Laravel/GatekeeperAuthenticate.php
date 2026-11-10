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
 * Verifies the access token and stores the Principal on the request.
 * Failures are 401 with WWW-Authenticate: Bearer error="invalid_token"
 * (TOKENS.md). A DPoP-bound token is accepted only as "DPoP <token>" with a
 * valid proof in the DPoP header (ADR-0070).
 */
final class GatekeeperAuthenticate
{
    public const ATTRIBUTE = 'gatekeeper.principal';

    public function __construct(private readonly Gatekeeper $gatekeeper, private readonly string $publicUrl = '')
    {
    }

    public function handle(Request $request, Closure $next): Response
    {
        $auth = (string) $request->header('Authorization', '');
        $dpop = str_starts_with($auth, 'DPoP ');
        $token = $dpop ? substr($auth, 5) : $request->bearerToken();
        if ($token === null || $token === '') {
            return new Response('unauthorized', 401, ['WWW-Authenticate' => 'Bearer']);
        }
        $bound = false;
        try {
            $principal = $this->gatekeeper->verify($token);
            $bound = $principal->jkt !== '';
            if ($bound !== $dpop) {
                throw new InvalidTokenException('wrong authorization scheme for this token');
            }
            if ($bound) {
                $base = $this->publicUrl !== '' ? rtrim($this->publicUrl, '/') : $request->getSchemeAndHttpHost();
                $this->gatekeeper->verifyDPoP($principal, $token, (string) $request->header('DPoP', ''), $request->getMethod(),
                    $base . $request->getPathInfo());
            }
        } catch (InvalidTokenException) {
            $challenge = $dpop || $bound ? 'DPoP error="invalid_token", algs="ES256 RS256 EdDSA"' : 'Bearer error="invalid_token"';
            return new Response('unauthorized', 401, ['WWW-Authenticate' => $challenge]);
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
