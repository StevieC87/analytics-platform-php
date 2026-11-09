<?php
// Laravel: found by package discovery. Builds the platform (firewall, error
// monitoring, server analytics) from config/analytics-firewall.php (the .env
// keys there) and, unless 'global' is off, puts its middleware first in
// every request. Errors Laravel reports go to the Errors report too, and
// with 'capture_logs' the exceptions your code logs. Rate
// limits count in the app's cache store, so APCu isn't needed. Every database
// query is timed for Server speed (QueryExecuted, what DB::listen hears), and
// every call of its Http client (its RequestSending and ResponseReceived
// events), every Redis command (CommandExecuted, with Laravel's Redis events
// turned on), and the queues are read from queue:work (QueueWatch).
//
// In your code: app(AnalyticsPlatform\Platform::class)->track('purchase', [...]).

namespace AnalyticsPlatform\Laravel;

use AnalyticsPlatform\Firewall;
use AnalyticsPlatform\Platform;
use AnalyticsPlatform\Queries;
use AnalyticsPlatform\TimedRedis;
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
                // The package's own: on a Redis cache, not timed.
                $counter = function ($key, $ttl) {
                    return Queries::untimed(function () use ($key, $ttl) {
                        Cache::add($key, 0, $ttl);
                        return (int) Cache::increment($key);
                    });
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
                'queries' => (bool) ($config['queries'] ?? true),
                'calls' => (bool) ($config['calls'] ?? true),
                'queues' => (bool) ($config['queues'] ?? true),
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
        // And its queries are its own.
        $this->queries();
        $this->redis();
        // Jobs added count in every process; the worker reads its queues.
        $this->queueBacklog();
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
    // shown before an error, and each call's time for Server speed → Calls,
    // from RequestSending to ResponseReceived (or ConnectionFailed). Its
    // events are public, so nothing is patched. ResponseReceived comes once
    // the body is in too, so a call's time includes reading it.
    private function breadcrumbs()
    {
        $events = $this->app['events'];
        if (class_exists('Illuminate\\Http\\Client\\Events\\ResponseReceived')) {
            $timed = (bool) $this->app['config']->get('analytics-firewall.performance', true)
                && (bool) $this->app['config']->get('analytics-firewall.calls', true);
            // The calls sent and not answered yet: their request, method,
            // address and start. ResponseReceived hands back the same request;
            // ConnectionFailed may make a new one, found by method and address.
            $pending = array();
            if ($timed && class_exists('Illuminate\\Http\\Client\\Events\\RequestSending')) {
                $events->listen('Illuminate\\Http\\Client\\Events\\RequestSending', function ($e) use (&$pending) {
                    try {
                        if (count($pending) >= 100) {
                            array_shift($pending);
                        }
                        $pending[] = array($e->request, (string) $e->request->method(), (string) $e->request->url(), microtime(true));
                    } catch (\Throwable $error) {
                        // untimed
                    }
                });
            }
            $answered = function ($request, $status) use (&$pending) {
                try {
                    $method = (string) $request->method();
                    $url = (string) $request->url();
                    // Its own request, else the oldest one sent to that address.
                    $found = null;
                    foreach ($pending as $i => $item) {
                        if ($item[0] === $request) {
                            $found = $i;
                            break;
                        }
                    }
                    if ($found === null) {
                        foreach ($pending as $i => $item) {
                            if ($item[1] === $method && $item[2] === $url) {
                                $found = $i;
                                break;
                            }
                        }
                    }
                    if ($found === null) {
                        return;
                    }
                    $started = $pending[$found][3];
                    array_splice($pending, $found, 1);
                    $this->app->make(Platform::class)->recordCall($method, $url, (microtime(true) - $started) * 1000, $status);
                } catch (\Throwable $error) {
                    // untimed
                }
            };
            // A listener that throws would reach the code that made the call.
            $events->listen('Illuminate\\Http\\Client\\Events\\ResponseReceived', function ($e) use ($answered) {
                try {
                    $this->app->make(Platform::class)->addRequestBreadcrumb($e->request->method(), $e->request->url(), $e->response->status());
                    $answered($e->request, (int) $e->response->status());
                } catch (\Throwable $error) {
                    // untimed
                }
            });
            $events->listen('Illuminate\\Http\\Client\\Events\\ConnectionFailed', function ($e) use ($answered) {
                try {
                    $this->app->make(Platform::class)->addRequestBreadcrumb($e->request->method(), $e->request->url(), 0);
                    $answered($e->request, 0);
                } catch (\Throwable $error) {
                    // untimed
                }
            });
        }
        // Octane serves many requests from one process.
        if (class_exists('Illuminate\\Foundation\\Http\\Events\\RequestHandled')) {
            $events->listen('Illuminate\\Foundation\\Http\\Events\\RequestHandled', function () {
                $this->app->make(Platform::class)->clearBreadcrumbs();
            });
        }
    }

    // Database queries (sdk/protocols/queries.md): QueryExecuted is what
    // DB::listen() listens for, on every connection, so this is DB::listen
    // without making a connection first. Its time is Laravel's own, in ms.
    // MongoDB connections (mongodb/laravel-mongodb) are left to the mongodb
    // extension's subscriber (Queries), which times the same commands.
    //
    // Laravel announces no failed query, so a failure is counted when its
    // QueryException is reported, with no time (0 ms): one your code catches
    // and doesn't report isn't counted at all.
    private function queries()
    {
        $config = $this->app['config'];
        if (!$config->get('analytics-firewall.performance', true) || !$config->get('analytics-firewall.queries', true)) {
            return;
        }
        $platform = null;
        $events = $this->app['events'];
        $events->listen('Illuminate\\Database\\Events\\QueryExecuted', function ($e) use (&$platform) {
            $driver = isset($e->connection) && is_object($e->connection) && method_exists($e->connection, 'getDriverName')
                ? (string) $e->connection->getDriverName() : '';
            if ($driver === 'mongodb') {
                return;
            }
            $platform = $platform ?: $this->app->make(Platform::class);
            $platform->recordQuery(Queries::databaseOfDriver($driver), (string) $e->sql, (float) $e->time);
        });
        $handler = $this->app->make(ExceptionHandler::class);
        if (method_exists($handler, 'reportable')) {
            $handler->reportable(function (\Throwable $error) use ($config) {
                if (!$error instanceof \Illuminate\Database\QueryException) {
                    return;
                }
                $name = isset($error->connectionName) ? (string) $error->connectionName : (string) $config->get('database.default');
                $driver = (string) $config->get('database.connections.' . $name . '.driver');
                if ($driver !== 'mongodb') {
                    $this->app->make(Platform::class)->recordQuery(Queries::databaseOfDriver($driver), (string) $error->getSql(), 0.0, true);
                }
            });
        }
        // Octane serves many requests from one process: each starts afresh.
        $events->listen('Laravel\\Octane\\Events\\RequestReceived', function () {
            $this->app->make(Platform::class)->beginRequest();
        });
    }

    // Redis commands (queries.md, "Redis"): CommandExecuted, which Laravel
    // fires for every command once its Redis events are on (enableEvents(),
    // turned on here, for connections made before too), with its own time
    // in ms. Each is "GET user:?:cart": the command and its first key's
    // shape, never an argument or value. Laravel 12's CommandFailed is a
    // failed command, with no time (0 ms); before Laravel 12 nothing says a
    // command failed, and phpredis answers an error reply with false rather
    // than an exception, so on phpredis those aren't seen as failed either.
    // Predis' pipeline() and transaction() are one event, "PIPELINE" or
    // "MULTI"; phpredis' run on the client itself, so Laravel announces none
    // of their commands. Blocking commands (BLPOP, XREAD with a block...) and
    // the package's own (the queue readings, the firewall's counter) aren't
    // timed.
    private function redis()
    {
        $config = $this->app['config'];
        if (!$config->get('analytics-firewall.performance', true) || !$config->get('analytics-firewall.queries', true)) {
            return;
        }
        $platform = null;
        $record = function ($e, $ms, $failed) use (&$platform) {
            try {
                // A Predis connection's parameters are in Predis' order (its eval_ro).
                $statement = TimedRedis::statementOf(isset($e->command) ? $e->command : null,
                    isset($e->parameters) && is_array($e->parameters) ? $e->parameters : array(),
                    isset($e->connection) && $e->connection instanceof \Illuminate\Redis\Connections\PredisConnection);
                if ($statement === null) {
                    return;
                }
                $platform = $platform ?: $this->app->make(Platform::class);
                $platform->recordQuery('redis', $statement, $ms, $failed);
            } catch (\Throwable $error) {
                // untimed
            }
        };
        $events = $this->app['events'];
        $events->listen('Illuminate\\Redis\\Events\\CommandExecuted', function ($e) use ($record) {
            $record($e, isset($e->time) ? (float) $e->time : 0.0, false);
        });
        $events->listen('Illuminate\\Redis\\Events\\CommandFailed', function ($e) use ($record) {
            $record($e, 0.0, true);
        });
        $enable = function ($redis) use ($events) {
            try {
                if (!is_object($redis) || !method_exists($redis, 'enableEvents')) {
                    return;
                }
                $redis->enableEvents();
                // Connections made before have no dispatcher to fire with.
                foreach (method_exists($redis, 'connections') ? (array) $redis->connections() : array() as $connection) {
                    if (is_object($connection) && method_exists($connection, 'getEventDispatcher')
                        && method_exists($connection, 'setEventDispatcher') && $connection->getEventDispatcher() === null) {
                        $connection->setEventDispatcher($events);
                    }
                }
            } catch (\Throwable $error) {
                // untimed
            }
        };
        if (method_exists($this->app, 'resolved') && $this->app->resolved('redis')) {
            $enable($this->app['redis']);
        } elseif (method_exists($this->app, 'afterResolving')) {
            $this->app->afterResolving('redis', $enable);
        }
    }

    // Job queues (sdk/protocols/queues.md), with Server speed: every
    // process counts the jobs it adds, and a queue:work worker counts those
    // it finishes and reads its queues between jobs, once a minute. Which
    // queues: the worker's own, and watch_queues ("redis:emails,default").
    private function queueBacklog()
    {
        $config = $this->app['config'];
        if (!$config->get('analytics-firewall.performance', true) || !$config->get('analytics-firewall.queues', true)
            || !class_exists('Illuminate\\Queue\\Events\\JobQueued')) {
            return;
        }
        $watch = new QueueWatch($this->app, $config->get('analytics-firewall.watch_queues', ''));
        $events = $this->app['events'];
        $events->listen('Illuminate\\Queue\\Events\\JobQueued', function ($e) use ($watch) {
            $watch->queued($e);
        });
        if (!$this->app->runningInConsole()) {
            return;
        }
        $events->listen('Illuminate\\Queue\\Events\\JobProcessed', function ($e) use ($watch) {
            $watch->finished($e, false);
        });
        $events->listen('Illuminate\\Queue\\Events\\JobFailed', function ($e) use ($watch) {
            $watch->finished($e, true);
        });
        // Looping's listeners can stop the worker by returning false: this
        // one returns nothing.
        $events->listen('Illuminate\\Queue\\Events\\Looping', function ($e) use ($watch) {
            $watch->looping($e);
        });
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
            'session_id' => self::sessionOf($request),
        );
    }

    // The visitor's session from the request itself, not $_SERVER/$_COOKIE,
    // which under Octane are the worker's.
    private static function sessionOf($request)
    {
        if (!$request) {
            return '';
        }
        $value = (string) ($request->headers->get('X-Analytics-Session') ?: $request->cookies->get(Platform::SESSION_COOKIE));
        return preg_match('/^[0-9a-f-]{36}$/Di', $value) ? strtolower($value) : '';
    }
}
