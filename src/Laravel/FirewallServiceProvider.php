<?php
// Laravel: found by package discovery. Builds the platform (firewall, error
// monitoring, server analytics) from config/analytics-firewall.php (the .env
// keys there) and, unless 'global' is off, puts its middleware first in
// every request. Errors Laravel reports go to the Errors report too, and
// with 'capture_logs' the exceptions your code logs. Rate
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
                'server_name' => $config['server_name'] ?? null,
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
        // Before the return below: a queue job's calls are steps of its trail too.
        $this->breadcrumbs();
        if ($this->app->runningInConsole()) {
            $this->queueJobs();
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
        // A fatal error ends the request before the middleware's terminate():
        // Laravel reports it from its own shutdown function, registered before
        // this one, so by the time this runs it is waiting to be sent.
        register_shutdown_function(function () {
            $this->app->make(Platform::class)->sendErrors();
        });
        // Errors Laravel reports (what it logs), from requests and elsewhere.
        $handler = $this->app->make(ExceptionHandler::class);
        if (method_exists($handler, 'reportable')) {
            $handler->reportable(function (\Throwable $error) {
                $this->app->make(Platform::class)->captureException($error, $this->requestFields(), 500, 'error');
            });
        }
        // Exceptions logged at error or above. One Laravel just reported is
        // logged too, and isn't sent a second time.
        if ($this->app['config']->get('analytics-firewall.capture_logs') && class_exists('Illuminate\\Log\\Events\\MessageLogged')) {
            $this->app['events']->listen('Illuminate\\Log\\Events\\MessageLogged', function ($e) {
                $error = isset($e->context['exception']) ? $e->context['exception'] : null;
                if ($error instanceof \Throwable && in_array($e->level, array('error', 'critical', 'alert', 'emergency'), true)) {
                    $this->app->make(Platform::class)->captureException($error, $this->requestFields(), 0, 'logged');
                }
            });
        }
    }

    // What Laravel's HTTP client asked other services for: steps in the trail
    // shown before an error. Its events are public, so nothing is patched.
    private function breadcrumbs()
    {
        $events = $this->app['events'];
        if (class_exists('Illuminate\\Http\\Client\\Events\\ResponseReceived')) {
            $events->listen('Illuminate\\Http\\Client\\Events\\ResponseReceived', function ($e) {
                $this->app->make(Platform::class)->addRequestBreadcrumb($e->request->method(), $e->request->url(), $e->response->status());
            });
            $events->listen('Illuminate\\Http\\Client\\Events\\ConnectionFailed', function ($e) {
                $this->app->make(Platform::class)->addRequestBreadcrumb($e->request->method(), $e->request->url(), 0);
            });
        }
        // Octane serves many requests from one process.
        if (class_exists('Illuminate\\Foundation\\Http\\Events\\RequestHandled')) {
            $events->listen('Illuminate\\Foundation\\Http\\Events\\RequestHandled', function () {
                $this->app->make(Platform::class)->clearBreadcrumbs();
            });
        }
    }

    // Queue workers (queue:work): each job is timed and its errors sent with
    // the job's name as their route, after every job, since a worker never
    // reaches the end of a request.
    private function queueJobs()
    {
        $config = $this->app['config'];
        // Either one: with errors off, the jobs are still timed.
        if (!($config->get('analytics-firewall.errors') || $config->get('analytics-firewall.performance', true))
            || !class_exists('Illuminate\\Queue\\Events\\JobProcessing')) {
            return;
        }
        $events = $this->app['events'];
        $events->listen('Illuminate\\Queue\\Events\\JobProcessing', function ($e) {
            $this->app->make(Platform::class)->startJob($e->job->resolveName());
        });
        $events->listen('Illuminate\\Queue\\Events\\JobProcessed', function () {
            $this->app->make(Platform::class)->endJob(false);
        });
        $events->listen('Illuminate\\Queue\\Events\\JobExceptionOccurred', function ($e) {
            $platform = $this->app->make(Platform::class);
            $platform->captureException($e->exception, null, 500, 'error');
            $platform->endJob(true);
        });
    }

    // The request being handled, as the Errors report and Server speed name it.
    private function requestFields()
    {
        $request = request();
        $route = $request && $request->route() ? $request->route()->uri() : '';
        return array(
            'method' => $request ? $request->method() : '',
            'path' => $request ? '/' . ltrim($request->path(), '/') : '',
            'route' => $route ? '/' . ltrim($route, '/') : '',
            'session_id' => Platform::sessionIdFromRequest(),
        );
    }
}
