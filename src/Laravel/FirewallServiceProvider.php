<?php
// Laravel: found by package discovery. Builds the platform (firewall, error
// monitoring, server analytics) from config/analytics-firewall.php (the .env
// keys there) and, unless 'global' is off, puts its middleware first in
// every request. Errors Laravel reports go to the Errors report too. Rate
// limits count in the app's cache store, so APCu isn't needed.
//
// In your code: app(AnalyticsPlatform\Platform::class)->track('purchase', [...]).

namespace AnalyticsPlatform\Laravel;

use AnalyticsPlatform\Firewall;
use AnalyticsPlatform\Platform;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\ServiceProvider;

class FirewallServiceProvider extends ServiceProvider
{
    public function register()
    {
        $this->mergeConfigFrom(__DIR__ . '/config.php', 'analytics-firewall');
        $this->app->singleton(Platform::class, function ($app) {
            $config = $app['config']->get('analytics-firewall');
            $counter = null;
            if ($app['config']->get('cache.default') !== 'array') {
                $counter = function ($key, $ttl) {
                    Cache::add($key, 0, $ttl);
                    return (int) Cache::increment($key);
                };
            }
            return new Platform(array(
                'site_id' => $config['site_id'],
                'secret' => $config['secret'],
                'endpoint' => $config['endpoint'],
                'storage' => storage_path('framework/analytics-firewall'),
                'platform' => 'laravel',
                'proxy' => (bool) ($config['proxy'] ?? true),
                'firewall' => $config['firewall'] ? array('mode' => $config['mode'] ?: null, 'counter' => $counter) : false,
                'errors' => (bool) $config['errors'],
                'analytics' => (bool) $config['analytics'],
                'performance' => (bool) ($config['performance'] ?? true),
                // composer.lock is in the app's root.
                'inventory' => ($config['inventory'] ?? true) ? array('root' => base_path()) : false,
                // Only the folder the web server serves is walked.
                'posture' => ($config['posture'] ?? false) ? array('roots' => array(public_path())) : false,
            ));
        });
        // The firewall on its own, for code that only needs check().
        $this->app->singleton(Firewall::class, function ($app) {
            return $app->make(Platform::class)->firewall();
        });
    }

    public function boot()
    {
        $this->publishes(array(__DIR__ . '/config.php' => config_path('analytics-firewall.php')), 'analytics-firewall');
        if ($this->app->runningInConsole()) {
            return;
        }
        if ($this->app['config']->get('analytics-firewall.global')) {
            $this->app->make(Kernel::class)->prependMiddleware(FirewallMiddleware::class);
        }
        // Failed logins (Laravel's auth) count for bot protection.
        if (class_exists('Illuminate\\Auth\\Events\\Failed')) {
            $this->app['events']->listen('Illuminate\\Auth\\Events\\Failed', function () {
                $request = request();
                $this->app->make(Platform::class)->loginFailed($request ? (string) $request->ip() : null);
            });
        }
        // The audit log: Laravel's auth events.
        $audit = array(
            'Illuminate\\Auth\\Events\\Login' => 'user.login',
            'Illuminate\\Auth\\Events\\Logout' => 'user.logout',
            'Illuminate\\Auth\\Events\\Registered' => 'user.registered',
            'Illuminate\\Auth\\Events\\PasswordReset' => 'user.password_reset',
            'Illuminate\\Auth\\Events\\Verified' => 'user.verified',
        );
        foreach ($audit as $event => $action) {
            if (class_exists($event)) {
                $this->app['events']->listen($event, function ($e) use ($action) {
                    $user = isset($e->user) ? $e->user : null;
                    $who = $user ? (string) ($user->email ?? $user->getAuthIdentifier()) : '';
                    $this->app->make(Platform::class)->audit($action, $who);
                });
            }
        }
        // Errors Laravel reports (what it logs), from requests and elsewhere.
        $handler = $this->app->make(ExceptionHandler::class);
        if (method_exists($handler, 'reportable')) {
            $handler->reportable(function (\Throwable $error) {
                $request = request();
                $route = $request && $request->route() ? $request->route()->uri() : '';
                $this->app->make(Platform::class)->captureException($error, array(
                    'method' => $request ? $request->method() : '',
                    'path' => $request ? '/' . ltrim($request->path(), '/') : '',
                    'route' => $route ? '/' . ltrim($route, '/') : '',
                    'session_id' => Platform::sessionIdFromRequest(),
                ), 500, 'error');
            });
        }
    }
}
