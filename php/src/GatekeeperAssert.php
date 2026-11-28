<?php

declare(strict_types=1);

namespace Gatekeeper;

use Gatekeeper\Laravel\MarkPublic;
use Gatekeeper\Laravel\RequirePermission;
use Gatekeeper\Laravel\RequirePermissionOn;
use Gatekeeper\Laravel\RequireSignedIn;
use Gatekeeper\Laravel\RequireStepUp;

/**
 * Checks in a test that every route has a Gatekeeper guard (FR-S20, ADR-0149):
 *
 *     GatekeeperAssert::everyRouteGuarded(Route::getRoutes());
 *
 * gk.can, gk.can_on and gk.stepup guard a route; gk.public and gk.signed_in mark the
 * deliberately open and the token-only ones. It reads each route's middleware and
 * never runs a route.
 */
final class GatekeeperAssert
{
    private const GUARDS = ['gk.can', 'gk.can_on', 'gk.stepup', 'gk.public', 'gk.signed_in',
        RequirePermission::class, RequirePermissionOn::class, RequireStepUp::class, MarkPublic::class, RequireSignedIn::class];

    private const WITH_PERMISSION = ['gk.can', 'gk.can_on', RequirePermission::class, RequirePermissionOn::class];

    /**
     * The routes with no guard ("GET /orders") and the permissions no route guards.
     *
     * @param iterable<object> $routes anything with methods(), uri() and gatherMiddleware(), as Laravel's routes have
     * @param list<string> $permissions the manifest's keys
     * @param list<string> $ignore "GET /health" or "/health"
     * @return array{unguarded: list<string>, unused: list<string>}
     */
    public static function check(iterable $routes, array $permissions = [], array $ignore = []): array
    {
        $unguarded = [];
        $used = [];
        foreach ($routes as $route) {
            $uri = '/' . ltrim((string) $route->uri(), '/');
            $methods = array_values(array_diff((array) $route->methods(), ['HEAD']));
            $guarded = false;
            foreach ((array) $route->gatherMiddleware() as $m) {
                if (!is_string($m)) {
                    continue;
                }
                [$name, $args] = array_pad(explode(':', $m, 2), 2, '');
                if (in_array($name, self::GUARDS, true)) {
                    $guarded = true;
                    if ($args !== '' && in_array($name, self::WITH_PERMISSION, true)) {
                        $used[str_replace(',', ':', $args)] = true; // Laravel joins middleware parameters with commas
                    }
                }
            }
            foreach ($methods === [] ? ['ANY'] : $methods as $method) {
                $name = "{$method} {$uri}";
                if (!$guarded && !in_array($name, $ignore, true) && !in_array($uri, $ignore, true)) {
                    $unguarded[$name] = true;
                }
            }
        }
        $names = array_keys($unguarded);
        sort($names);
        $unused = array_values(array_filter($permissions, static fn (string $p): bool => !isset($used[$p])));
        sort($unused);
        return ['unguarded' => $names, 'unused' => $unused];
    }

    /**
     * Throws UnguardedRoutesException, listing them, when a route has no guard, or
     * (with $failOnUnused) a permission no route guards.
     *
     * @param iterable<object> $routes
     * @param list<string> $permissions
     * @param list<string> $ignore
     * @return array{unguarded: list<string>, unused: list<string>}
     */
    public static function everyRouteGuarded(iterable $routes, array $permissions = [], bool $failOnUnused = false, array $ignore = []): array
    {
        $r = self::check($routes, $permissions, $ignore);
        $problems = [];
        if ($r['unguarded'] !== []) {
            $problems[] = count($r['unguarded']) . " route(s) with no Gatekeeper guard (gk.can, gk.can_on, gk.stepup, gk.public or gk.signed_in):\n  "
                . implode("\n  ", $r['unguarded']);
        }
        if ($failOnUnused && $r['unused'] !== []) {
            $problems[] = 'permission(s) no route guards: ' . implode(', ', $r['unused']);
        }
        if ($problems !== []) {
            throw new UnguardedRoutesException($r['unguarded'], $r['unused'], 'gatekeeper: ' . implode("\n", $problems));
        }
        return $r;
    }
}
