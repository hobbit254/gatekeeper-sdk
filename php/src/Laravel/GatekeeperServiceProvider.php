<?php

declare(strict_types=1);

namespace Gatekeeper\Laravel;

use Gatekeeper\Config;
use Gatekeeper\Gatekeeper;
use Illuminate\Contracts\Cache\Repository;
use Illuminate\Routing\Router;
use Illuminate\Support\ServiceProvider;

/** Binds Gatekeeper from config/gatekeeper.php and registers the 'gatekeeper' and 'gk.can' middleware. */
final class GatekeeperServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../../config/gatekeeper.php', 'gatekeeper');
        $this->app->singleton(Gatekeeper::class, function ($app): Gatekeeper {
            $c = $app['config']['gatekeeper'];
            return new Gatekeeper(
                new Config($c['issuer'], $c['audience'], $c['client_id'], (string) ($c['client_secret'] ?? '')),
                $app->make(Repository::class),
            );
        });
    }

    public function boot(): void
    {
        $this->publishes([__DIR__ . '/../../config/gatekeeper.php' => config_path('gatekeeper.php')], 'gatekeeper');
        if ($this->app->bound('router')) {
            /** @var Router $router */
            $router = $this->app['router'];
            $router->aliasMiddleware('gatekeeper', GatekeeperAuthenticate::class);
            $router->aliasMiddleware('gk.can', RequirePermission::class);
        }
    }
}
