<?php
// Laravel's queues for Health → Server speed → Jobs (sdk/protocols/queues.md,
// system "laravel"), from Laravel's public queue API and events only:
//
// - Every process counts the jobs it adds (JobQueued); a worker counts the
//   ones it finishes: JobProcessed when the job wasn't released back, and
//   JobFailed, which comes only once a job has failed for good.
// - A queue:work worker reads its queues between jobs (the Looping event),
//   at most once a minute: Queue::size(), or on Laravel versions whose
//   queue has them pendingSize(), delayedSize(), reservedSize() and
//   creationTimeOfOldestPendingJob(); failed from the failed-job store's
//   count(). Without pendingSize() waiting is size(), which counts the
//   delayed and running jobs too. Which queues: the ones the worker
//   processes, and those in the watch_queues setting.
//
// The broker is named by host, port and database from the connection's
// settings, never a user name or password. Nothing here may stop or slow
// the worker: Looping's listeners can stop it by returning false, so this
// one returns nothing, and every reading is caught.

namespace AnalyticsPlatform\Laravel;

use AnalyticsPlatform\Core;
use AnalyticsPlatform\Platform;

class QueueWatch
{
    const SYSTEM = 'laravel';
    // Drivers with no queue to read: the job runs at once, or nowhere.
    const NO_QUEUE = array('sync', 'null', 'deferred', 'background', 'failover');
    // Seconds the Looping listener may spend sending, of Core::DEADLINE's 5.
    const SEND_WITHIN = 2;

    private $app;
    // The watch_queues setting: "connection:queue" or "queue" (the default connection).
    private $extra = array();
    private $brokers = array();
    private $worker = false;

    public function __construct($app, $watch = '')
    {
        $this->app = $app;
        foreach (is_array($watch) ? $watch : explode(',', (string) $watch) as $item) {
            $item = trim((string) $item);
            if ($item === '') {
                continue;
            }
            $parts = explode(':', $item, 2);
            $this->extra[] = count($parts) === 2 ? array(trim($parts[0]), trim($parts[1])) : array(null, $item);
        }
    }

    private function queues()
    {
        return $this->app->make(Platform::class)->module('queues');
    }

    // JobQueued: a job this process added.
    public function queued($e)
    {
        try {
            $connection = isset($e->connectionName) ? (string) $e->connectionName : $this->defaultConnection();
            $queue = isset($e->queue) && is_string($e->queue) && $e->queue !== '' ? $e->queue
                : (isset($e->job) && is_object($e->job) && isset($e->job->queue) && is_string($e->job->queue) && $e->job->queue !== '' ? $e->job->queue : null);
            $this->count($connection, $queue, 1, $this->worker ? 0 : null);
        } catch (\Throwable $e) {
            // not counted
        }
    }

    // JobProcessed (done, unless it was released to run again) or JobFailed (for good).
    public function finished($e, $failed)
    {
        try {
            $job = isset($e->job) ? $e->job : null;
            // A job that called fail() itself and returned comes as JobFailed
            // and then JobProcessed: counted once, at JobFailed.
            if (!is_object($job) || (!$failed && ((method_exists($job, 'isReleased') && $job->isReleased())
                || (method_exists($job, 'hasFailed') && $job->hasFailed())))) {
                return;
            }
            $this->worker = true;
            $connection = isset($e->connectionName) ? (string) $e->connectionName : $this->defaultConnection();
            $this->count($connection, method_exists($job, 'getQueue') ? (string) $job->getQueue() : null, 0, 1);
        } catch (\Throwable $e) {
            // not counted
        }
    }

    // Looping: between two jobs of a queue:work worker. Returns nothing,
    // which lets the worker go on.
    public function looping($e)
    {
        try {
            $this->worker = true;
            $queues = $this->queues();
            if (!$queues || !$queues->readingDue()) {
                return;
            }
            $connection = isset($e->connectionName) && $e->connectionName !== '' ? (string) $e->connectionName : $this->defaultConnection();
            $watched = array();
            foreach (explode(',', isset($e->queue) ? (string) $e->queue : '') as $queue) {
                if (trim($queue) !== '') {
                    $watched[] = array($connection, trim($queue), true);
                }
            }
            foreach ($this->extra as $item) {
                $watched[] = array($item[0] !== null ? $item[0] : $this->defaultConnection(), $item[1], false);
            }
            $readings = array();
            $seen = array();
            foreach ($watched as $item) {
                list($name, $queue, $own) = $item;
                $broker = $this->brokerOf($name);
                if ($broker === null || isset($seen[$name . "\0" . $queue]) || count($readings) >= 100) {
                    continue;
                }
                $seen[$name . "\0" . $queue] = true;
                // This worker counts the jobs it adds to the queues it
                // works, and those it finishes from them: 0 is a count.
                if ($own) {
                    $queues->count(self::SYSTEM, $broker, $queue, 0, 0);
                }
                $readings[] = array('system' => self::SYSTEM, 'broker' => $broker, 'queue' => $queue) + $this->read($name, $queue);
            }
            $queues->record($readings);
            // A collector that doesn't answer holds the worker this long at
            // most, once a minute; what wasn't sent waits in the spool.
            $this->app->make(Platform::class)->core()->within(self::SEND_WITHIN, function () use ($queues) {
                $queues->flush();
            });
        } catch (\Throwable $e) {
            // the worker goes on
        }
    }

    private function count($connection, $queue, $added, $finished)
    {
        $queues = $this->queues();
        $broker = $this->brokerOf($connection);
        if (!$queues || $broker === null) {
            return;
        }
        if ($queue === null || $queue === '') {
            $queue = (string) ($this->config('queue.connections.' . $connection . '.queue') ?: 'default');
        }
        $queues->count(self::SYSTEM, $broker, $queue, $added, $finished);
    }

    // The gauges of one queue now; none of them when it couldn't be read.
    public function read($connection, $queue)
    {
        try {
            $q = $this->app['queue']->connection($connection);
            $out = array();
            $out['waiting'] = method_exists($q, 'pendingSize') ? (int) $q->pendingSize($queue) : (int) $q->size($queue);
            if (method_exists($q, 'delayedSize')) {
                $out['delayed'] = (int) $q->delayedSize($queue);
            }
            if (method_exists($q, 'reservedSize')) {
                $out['running'] = (int) $q->reservedSize($queue);
            }
            if ($out['waiting'] === 0) {
                $out['oldest_s'] = 0;
            } elseif (method_exists($q, 'creationTimeOfOldestPendingJob')) {
                $at = $q->creationTimeOfOldestPendingJob($queue);
                if (is_numeric($at) && $at > 0) {
                    $out['oldest_s'] = max(0, time() - (int) $at);
                }
            }
        } catch (\Throwable $e) {
            return array();
        }
        // The failed jobs kept: from the store, when it can count them.
        try {
            $failer = isset($this->app['queue.failer']) ? $this->app['queue.failer'] : null;
            if (is_object($failer) && method_exists($failer, 'count')) {
                $out['failed'] = (int) $failer->count($connection, $queue);
            }
        } catch (\Throwable $e) {
            // unknown, not zero
        }
        return $out;
    }

    // Where a connection's queues live: host:port/database, from its settings
    // (or its URL's host, port and path), never the user or password. null
    // for a driver with no queue.
    public function brokerOf($connection)
    {
        $connection = (string) $connection;
        if (array_key_exists($connection, $this->brokers)) {
            return $this->brokers[$connection];
        }
        $settings = $this->config('queue.connections.' . $connection);
        $broker = null;
        if (is_array($settings) && !empty($settings['driver']) && !in_array($settings['driver'], self::NO_QUEUE, true)) {
            $driver = (string) $settings['driver'];
            if ($driver === 'redis') {
                $name = isset($settings['connection']) ? (string) $settings['connection'] : 'default';
                $broker = self::address($this->config('database.redis.' . $name), 6379, 'database', 'redis');
            } elseif ($driver === 'database') {
                $name = isset($settings['connection']) && $settings['connection'] ? (string) $settings['connection'] : (string) $this->config('database.default');
                $db = $this->config('database.connections.' . $name);
                if (is_array($db) && isset($db['driver']) && $db['driver'] === 'sqlite') {
                    $broker = 'sqlite/' . basename((string) (isset($db['database']) ? $db['database'] : ''));
                } else {
                    $ports = array('mysql' => 3306, 'mariadb' => 3306, 'pgsql' => 5432, 'sqlsrv' => 1433);
                    $broker = self::address($db, is_array($db) && isset($db['driver'], $ports[$db['driver']]) ? $ports[$db['driver']] : 0, 'database', 'database');
                }
            } elseif ($driver === 'beanstalkd') {
                $broker = self::address($settings, 11300, null, 'beanstalkd');
            } elseif ($driver === 'sqs') {
                $host = isset($settings['prefix']) ? @parse_url((string) $settings['prefix'], PHP_URL_HOST) : null;
                $broker = is_string($host) && $host !== '' ? strtolower($host) : 'sqs' . (isset($settings['region']) ? '.' . $settings['region'] : '');
            } else {
                $broker = $driver;
            }
        }
        if ($broker !== null) {
            // Never a user name or password, whatever the settings held.
            $at = strrpos($broker, '@');
            $broker = substr(preg_replace('/\s/', '', $at === false ? $broker : substr($broker, $at + 1)), 0, 200);
        }
        return $this->brokers[$connection] = $broker === '' ? null : $broker;
    }

    // host:port/database from a connection's settings or its url. A url
    // holding an "@" that parse_url() didn't read as a user and password
    // (one with "#", "/" or "?" in the password, written unencoded) isn't
    // used: parse_url() would then take part of the password for the host
    // or the port. Its query (?password=...) is never read.
    private static function address($settings, $port, $dbKey, $fallback)
    {
        if (!is_array($settings)) {
            return $fallback;
        }
        $host = isset($settings['host']) ? $settings['host'] : null;
        $db = $dbKey !== null && isset($settings[$dbKey]) ? $settings[$dbKey] : null;
        if (isset($settings['port']) && is_numeric($settings['port'])) {
            $port = (int) $settings['port'];
        }
        // Predis' unix socket: scheme unix, the socket in path.
        if (isset($settings['scheme'], $settings['path']) && $settings['scheme'] === 'unix' && is_string($settings['path'])) {
            $host = $settings['path'];
        }
        if (!empty($settings['url']) && is_string($settings['url'])) {
            $url = @parse_url($settings['url']);
            if (preg_match('#^unix://(/[^?\#]+)#i', $settings['url'], $socket)) {
                $host = $socket[1];
            } elseif (is_array($url) && (strpos($settings['url'], '@') === false || isset($url['user']) || isset($url['pass']))) {
                $path = isset($url['path']) ? trim($url['path'], '/') : '';
                $host = isset($url['host']) ? $url['host'] : $host;
                $port = isset($url['port']) ? (int) $url['port'] : $port;
                $db = $path !== '' ? $path : $db;
            }
        }
        if (is_array($host)) {
            $host = reset($host);
        }
        // Whatever follows a "?" or "#" in a host setting is a query, not the host.
        $host = is_scalar($host) ? strtolower(preg_replace('/[?#].*/s', '', (string) $host)) : '';
        $host = $host !== '' ? $host : '127.0.0.1';
        // A unix socket is named by its file.
        if ($host[0] === '/') {
            $host = basename($host);
            $port = 0;
        } elseif ($host[0] !== '[' && filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            // An IPv6 address in brackets, so its port can be told from it.
            $host = '[' . $host . ']';
        }
        $db = $db !== null && is_scalar($db) ? preg_replace('/[?#].*/s', '', (string) $db) : '';
        return $host . ($port ? ':' . $port : '') . ($db !== '' ? '/' . $db : '');
    }

    private function defaultConnection()
    {
        return (string) ($this->config('queue.default') ?: 'sync');
    }

    private function config($key)
    {
        return $this->app['config']->get($key);
    }
}
