<?php
// Outgoing calls (sdk/protocols/calls.md), job queues (queues.md) and the
// ClickHouse query timer: each call added to the request it ran in by host
// only, the collector's own left out, a 4xx an answer and a 5xx or none a
// failure; the hooks (Guzzle's middleware, Laravel's Http events, Symfony's
// HttpClient decorator, WordPress's pre_http_request/http_api_debug) against
// stand-ins for the few classes they name; queries and calls filed under
// exactly the route Server speed filed the request under, "(other)" included
// (#373); Laravel's queues read from the worker's Looping event, gauges as
// the largest, counts summed, the minute still running held back; and
// TimedClickHouse in front of a stand-in client. The collector is a closed
// port, so what would be sent waits in the retry spools, where this reads it.
//
//   php test/CallsQueuesTest.php

namespace GuzzleHttp\Promise {
    class CancellationException extends \RuntimeException
    {
    }
    class Create
    {
        public static function rejectionFor($reason)
        {
            return \FakePromise::rejected($reason);
        }
    }
}

namespace Symfony\Component\HttpClient {
    trait AsyncDecoratorTrait
    {
        private $client;
    }
}

namespace Symfony\Contracts\HttpClient {
    interface HttpClientInterface
    {
    }
    interface ResponseInterface
    {
    }
    interface ChunkInterface
    {
    }
}

namespace Symfony\Contracts\HttpClient\Exception {
    interface TransportExceptionInterface extends \Throwable
    {
    }
}

namespace Symfony\Contracts\Service {
    interface ResetInterface
    {
    }
}

namespace Symfony\Component\HttpClient\Response {
    // Runs the passthru over the chunks the test hands in, as the real one
    // does as they arrive.
    class AsyncContext
    {
        public $url;
        public $status;

        public function __construct($url, $status)
        {
            $this->url = $url;
            $this->status = $status;
        }

        public function getInfo($name)
        {
            return $name === 'url' ? $this->url : null;
        }

        public function getStatusCode()
        {
            return $this->status;
        }
    }
    class AsyncResponse implements \Symfony\Contracts\HttpClient\ResponseInterface
    {
        public function __construct($client, $method, $url, array $options, callable $passthru)
        {
            $context = new AsyncContext($url, $options['status']);
            foreach ($options['chunks'] as $chunk) {
                if (isset($options['wait'])) {
                    usleep($options['wait']);
                }
                foreach ($passthru($chunk, $context) as $ignored) {
                }
            }
        }
    }
}

namespace Illuminate\Support {
    class ServiceProvider
    {
        public $app;

        public function __construct($app)
        {
            $this->app = $app;
        }

        protected function mergeConfigFrom($path, $key)
        {
        }

        protected function publishes(array $paths, $group = null)
        {
        }
    }
}

namespace Illuminate\Contracts\Debug {
    interface ExceptionHandler
    {
    }
}

namespace Illuminate\Contracts\Http {
    interface Kernel
    {
    }
}

namespace Illuminate\Http\Client\Events {
    class RequestSending
    {
    }
    class ResponseReceived
    {
    }
    class ConnectionFailed
    {
    }
}

namespace Illuminate\Queue\Events {
    class JobQueued
    {
    }
    class JobProcessing
    {
    }
}

namespace {
    foreach (glob(__DIR__ . '/../src/*.php') as $file) {
        require_once $file;
    }
    require_once __DIR__ . '/../src/Laravel/FirewallServiceProvider.php';
    require_once __DIR__ . '/../src/Laravel/QueueWatch.php';
    require_once __DIR__ . '/../src/Symfony/HttpClientBreadcrumbs.php';

    use AnalyticsPlatform\Laravel\FirewallServiceProvider;
    use AnalyticsPlatform\Platform;
    use AnalyticsPlatform\Queries;
    use AnalyticsPlatform\Symfony\HttpClientBreadcrumbs;
    use AnalyticsPlatform\TimedClickHouse;

    $failed = 0;
    $checked = 0;
    function check($name, $ok)
    {
        global $failed, $checked;
        $checked++;
        if (!$ok) {
            $failed++;
            fwrite(STDERR, "FAIL: $name\n");
        }
    }

    function storeOf($name)
    {
        return sys_get_temp_dir() . '/analytics-calls-test-' . $name . '-' . getmypid();
    }

    function platformAt($store, array $more = array())
    {
        return new Platform($more + array('site_id' => 'a1b2c3d4e5f6a1b2c3d4e5f6', 'secret' => 'the-site-secret',
            'endpoint' => 'http://127.0.0.1:9/', 'storage' => $store, 'server_name' => 'web-1',
            'firewall' => false, 'proxy' => false, 'inventory' => false, 'resources' => false, 'crawlers' => false));
    }

    // Nothing is sent until flush(true): the last send was just now.
    function hold(Platform $platform)
    {
        $platform->core()->ensureDir();
        foreach (array('queries', 'requests', 'queues') as $name) {
            touch($platform->core()->dir() . '/' . $name . '.lock');
        }
        return $platform;
    }

    function flushAll(Platform $platform)
    {
        $platform->module('performance')->flush(true);
        $timings = $platform->module('queries') ?: $platform->module('calls');
        $timings->flush(true);
    }

    // The bodies a spool kept to send again, for one path.
    function sent(Platform $platform, $spool, $path)
    {
        $file = $platform->core()->dir() . '/' . $spool . '.retry.jsonl';
        $bodies = array();
        foreach (is_file($file) ? file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : array() as $line) {
            $batch = json_decode($line, true);
            if ($batch['path'] === $path) {
                $bodies[] = $batch['body'];
            }
        }
        return $bodies;
    }

    function rowsOf(array $bodies)
    {
        $rows = array();
        foreach ($bodies as $body) {
            $rows = array_merge($rows, $body['rows']);
        }
        return $rows;
    }

    function cleanUp($store)
    {
        if (!is_dir($store)) {
            return;
        }
        $items = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($store, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
        foreach ($items as $item) {
            $item->isDir() ? @rmdir($item->getPathname()) : @unlink($item->getPathname());
        }
        @rmdir($store);
    }

    // ---- The host -------------------------------------------------------------------

    check('only the host, lower case, without the default port', Queries::hostOf('https://API.Stripe.com:443/v1/charges/ch_1?key=sk_live') === 'api.stripe.com');
    check('a port that isn\'t the scheme\'s is kept', Queries::hostOf('http://localhost:8080/x') === 'localhost:8080');
    check('an IPv6 host keeps its brackets', Queries::hostOf('http://[::1]:3000/') === '[::1]:3000');
    check('no host is nothing', Queries::hostOf('/relative/path') === '' && Queries::hostOf('not a url') === '');
    check('a ClickHouse driver is clickhouse', Queries::databaseOfDriver('clickhouse') === 'clickhouse' && Queries::databaseOf('clickhouse') === 'clickhouse');

    // ---- Recording calls --------------------------------------------------------------

    check('calls: false keeps queries', ($off = platformAt(storeOf('off'), array('calls' => false))) && in_array('queries', $off->modules(), true)
        && !$off->module('queries')->callsOn());
    $callsOnly = platformAt(storeOf('off'), array('queries' => false));
    check('queries: false keeps calls, under their own name', !in_array('queries', $callsOnly->modules(), true) && in_array('calls', $callsOnly->modules(), true));
    check('and performance: false leaves both out', !array_intersect(array('queries', 'calls', 'queues'), platformAt(storeOf('off'), array('performance' => false))->modules()));
    check('queues: false leaves the queues out', !in_array('queues', platformAt(storeOf('off'), array('queues' => false))->modules(), true));

    $platform = hold(platformAt(storeOf('main')));
    $platform->beginRequest();
    $platform->setRoute('/checkout');
    $platform->recordCall('post', 'https://API.Stripe.com/v1/charges/ch_1?key=secret', 310.0, 200);
    $platform->recordCall('POST', 'https://api.stripe.com/v1/refunds', 90.0, 402);
    $platform->recordCall('GET', 'https://mail.example.com/send', 1200.0, 503);
    $platform->recordCall('GET', 'https://down.example.com/', 5000.0, 0);
    $platform->recordCall('POST', 'http://127.0.0.1:9/events/server-calls', 3.0, 202);
    $platform->recordCall('GET', 'relative', 3.0, 200);
    for ($i = 0; $i < 55; $i++) {
        $platform->recordCall('GET', "https://h$i.example.com/", 1.0, 200);
    }
    $platform->recordQuery('postgresql', 'SELECT 1', 2.0);
    $platform->recordAndSend();
    $file = $platform->core()->dir() . '/requests.jsonl';
    $lines = array_map(function ($line) {
        return json_decode($line, true);
    }, file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES));
    $line = end($lines);
    $calls = array();
    foreach ($line['c'] as $c) {
        $calls[$c[0] . ' ' . $c[1]] = $c;
    }
    check('the request\'s calls ride in its line beside its queries', $line['r'] === '/checkout' && isset($line['q'], $line['c']));
    check('one host is one entry per call method, by host only', $calls['POST api.stripe.com'][2] === 2 && !isset($calls['GET down.example.com/']));
    check('a 4xx is an answer, not a failure', $calls['POST api.stripe.com'][3] === 0);
    check('a 5xx and no answer at all are failures', $calls['GET mail.example.com'][3] === 1 && $calls['GET down.example.com'][3] === 1);
    check('the package\'s own calls to the collector are left out', !isset($calls['POST 127.0.0.1:9']));
    check('past 50 hosts a request, new ones are "(other)"', count($line['c']) === 51 && isset($calls['GET (other)']));
    flushAll($platform);
    $rows = rowsOf(sent($platform, 'queries', '/events/server-calls'));
    $byHost = array();
    foreach ($rows as $row) {
        $byHost[$row['call_method'] . ' ' . $row['host']] = $row;
    }
    $stripe = isset($byHost['POST api.stripe.com']) ? $byHost['POST api.stripe.com'] : null;
    check('sent to /events/server-calls as the protocol has it', $stripe !== null && $stripe['method'] === 'GET' && $stripe['route'] === '/checkout'
        && $stripe['count'] === 2 && $stripe['errors'] === 0 && $stripe['sum_ms'] == 400.0 && $stripe['max_ms'] == 310.0
        && count($stripe['buckets']) === 12 && preg_match('/^\d{4}-\d\d-\d\dT\d\d:\d\d:00\.000Z$/', $stripe['minute']));
    $bodies = sent($platform, 'queries', '/events/server-calls');
    check('the body names the site, server and PHP, with the bearer secret', $bodies && $bodies[0]['site_id'] === 'a1b2c3d4e5f6a1b2c3d4e5f6'
        && $bodies[0]['server_name'] === 'web-1' && strpos($bodies[0]['runtime'], 'PHP ') === 0);
    check('and its queries went to /events/server-queries', count(rowsOf(sent($platform, 'queries', '/events/server-queries'))) === 1);

    // calls: false: nothing recorded.
    $quiet = hold(platformAt(storeOf('quiet'), array('calls' => false)));
    $quiet->beginRequest();
    $quiet->recordCall('GET', 'https://api.example.com/', 5.0, 200);
    $quiet->recordAndSend();
    $quietLines = file($quiet->core()->dir() . '/requests.jsonl', FILE_IGNORE_NEW_LINES);
    check('calls: false records no call', strpos(end($quietLines), '"c"') === false);

    // Outside a request or job: JOB (background), sent as the script ends.
    $cli = platformAt(storeOf('cli'), array('queries' => false));
    $cli->recordCall('GET', 'https://api.example.com/sync', 40.0, 200);
    $cli->module('calls')->onShutdown();
    $background = rowsOf(sent($cli, 'queries', '/events/server-calls'));
    check('a call outside a request is JOB (background)', count($background) === 1 && $background[0]['method'] === 'JOB'
        && $background[0]['route'] === '(background)' && $background[0]['host'] === 'api.example.com');

    // A job's calls are the job's own.
    $jobs = hold(platformAt(storeOf('jobs')));
    $jobs->job('sync-orders', function () use ($jobs) {
        $jobs->recordCall('GET', 'https://shop.example.com/orders', 70.0, 200);
    });
    flushAll($jobs);
    $jobCalls = rowsOf(sent($jobs, 'queries', '/events/server-calls'));
    check('a job\'s calls go under its JOB row', count($jobCalls) === 1 && $jobCalls[0]['method'] === 'JOB' && $jobCalls[0]['route'] === '/(job) sync-orders');

    // ---- #373: filed under exactly what Server speed filed --------------------------------

    // 300 routes with no queries fill Server speed's minute; the next ones
    // fold into "(other)", and so must their queries and calls.
    $fold = hold(platformAt(storeOf('fold')));
    for ($r = 0; $r < 300; $r++) {
        $fold->beginRequest();
        $fold->setRoute('/plain/' . $r);
        $fold->recordAndSend();
    }
    for ($r = 0; $r < 5; $r++) {
        $fold->beginRequest();
        $fold->setRoute('/late/' . $r);
        $fold->recordQuery('mysql', "SELECT * FROM late WHERE id = $r", 2.0);
        $fold->recordCall('GET', 'https://api.example.com/late', 9.0, 200);
        $fold->recordAndSend();
    }
    flushAll($fold);
    $timed = array();
    foreach (rowsOf(sent($fold, 'requests', '/events/server-requests')) as $row) {
        $timed[$row['method'] . ' ' . $row['route']] = true;
    }
    $queryRows = rowsOf(sent($fold, 'queries', '/events/server-queries'));
    $callRows = rowsOf(sent($fold, 'queries', '/events/server-calls'));
    $unjoined = array_filter(array_merge($queryRows, $callRows), function ($row) use ($timed) {
        return !isset($timed[$row['method'] . ' ' . $row['route']]);
    });
    check('Server speed folded the late routes', isset($timed['GET (other)']) && !isset($timed['GET /late/0']));
    check('their queries and calls are under "(other)" too, so every row joins', $queryRows && $callRows && !$unjoined
        && $queryRows[0]['route'] === '(other)' && $callRows[0]['route'] === '(other)' && $callRows[0]['count'] === 5);

    // ---- Guzzle -------------------------------------------------------------------------

    class FakePromise
    {
        private $value;
        private $rejected;

        public function __construct($value, $rejected)
        {
            $this->value = $value;
            $this->rejected = $rejected;
        }

        public static function rejected($reason)
        {
            return new self($reason, true);
        }

        public function then(?callable $ok = null, ?callable $fail = null)
        {
            if ($this->rejected) {
                return $fail ? $fail($this->value) : $this;
            }
            return new self($ok ? $ok($this->value) : $this->value, false);
        }

        public function isRejected()
        {
            return $this->rejected;
        }
    }

    class FakePsrRequest
    {
        private $method;
        private $uri;

        public function __construct($method, $uri)
        {
            $this->method = $method;
            $this->uri = $uri;
        }

        public function getMethod()
        {
            return $this->method;
        }

        public function getUri()
        {
            return $this->uri;
        }
    }

    class FakePsrResponse
    {
        private $status;

        public function __construct($status)
        {
            $this->status = $status;
        }

        public function getStatusCode()
        {
            return $this->status;
        }
    }

    class FakeRequestException extends RuntimeException
    {
        private $response;

        public function __construct($response)
        {
            parent::__construct('failed');
            $this->response = $response;
        }

        public function getResponse()
        {
            return $this->response;
        }
    }

    $guzzle = hold(platformAt(storeOf('guzzle')));
    $guzzle->beginRequest();
    $guzzle->setRoute('/guzzle');
    $theirs = 0;
    $middleware = $guzzle->guzzleMiddleware();
    // The headers come after 20 ms, the body after another 150.
    $handler = function ($request, array $options) {
        usleep(20000);
        $options['on_headers'](new FakePsrResponse(200));
        usleep(150000);
        return new FakePromise(new FakePsrResponse(200), false);
    };
    $answer = $middleware($handler)(new FakePsrRequest('GET', 'https://cdn.example.com/a.json'), array('on_headers' => function () use (&$theirs) {
        $theirs++;
    }));
    check('the answer is handed on, and an on_headers of yours still runs', $answer->then()->isRejected() === false && $theirs === 1);
    $failing = function ($reason) {
        return function () use ($reason) {
            return FakePromise::rejected($reason);
        };
    };
    $rejected = $middleware($failing(new FakeRequestException(new FakePsrResponse(503))))(new FakePsrRequest('POST', 'https://pay.example.com/'), array());
    $middleware($failing(new RuntimeException('could not connect')))(new FakePsrRequest('GET', 'https://gone.example.com/'), array());
    $middleware($failing(new GuzzleHttp\Promise\CancellationException('cancelled')))(new FakePsrRequest('GET', 'https://cancelled.example.com/'), array());
    $guzzle->recordAndSend();
    flushAll($guzzle);
    $byHost = array();
    foreach (rowsOf(sent($guzzle, 'queries', '/events/server-calls')) as $row) {
        $byHost[$row['host']] = $row;
    }
    check('a rejection is still a rejection', $rejected->isRejected());
    check('Guzzle\'s call is timed to its headers, not its body', isset($byHost['cdn.example.com']) && $byHost['cdn.example.com']['max_ms'] >= 15
        && $byHost['cdn.example.com']['max_ms'] < 120 && $byHost['cdn.example.com']['errors'] === 0);
    check('a 5xx that http_errors threw is a failed call', isset($byHost['pay.example.com']) && $byHost['pay.example.com']['errors'] === 1
        && $byHost['pay.example.com']['call_method'] === 'POST');
    check('no answer is a failed call', isset($byHost['gone.example.com']) && $byHost['gone.example.com']['errors'] === 1);
    check('a call the code cancelled isn\'t counted', !isset($byHost['cancelled.example.com']));

    // ---- Symfony HttpClient -------------------------------------------------------------

    class FakeChunk implements Symfony\Contracts\HttpClient\ChunkInterface
    {
        private $throws;
        private $first;

        public function __construct($first, $throws = false)
        {
            $this->first = $first;
            $this->throws = $throws;
        }

        public function isTimeout()
        {
            if ($this->throws) {
                throw new FakeTransportException('refused');
            }
            return false;
        }

        public function getInformationalStatus()
        {
            return null;
        }

        public function isFirst()
        {
            return $this->first;
        }
    }

    class FakeTransportException extends RuntimeException implements Symfony\Contracts\HttpClient\Exception\TransportExceptionInterface
    {
    }

    class FakeTransport implements Symfony\Contracts\HttpClient\HttpClientInterface
    {
    }

    $symfony = hold(platformAt(storeOf('symfony'), array('platform' => 'symfony')));
    $symfony->beginRequest();
    $symfony->setRoute('/symfony');
    $client = new HttpClientBreadcrumbs(new FakeTransport(), $symfony);
    $client->request('GET', 'https://api.example.org/items?page=2', array('status' => 200, 'wait' => 10000, 'chunks' => array(new FakeChunk(true), new FakeChunk(false))));
    $client->request('GET', 'https://down.example.org/', array('status' => 0, 'chunks' => array(new FakeChunk(false, true))));
    $symfony->recordAndSend();
    flushAll($symfony);
    $byHost = array();
    foreach (rowsOf(sent($symfony, 'queries', '/events/server-calls')) as $row) {
        $byHost[$row['host']] = $row;
    }
    check('Symfony\'s HttpClient calls are timed at their first chunk', isset($byHost['api.example.org']) && $byHost['api.example.org']['count'] === 1
        && $byHost['api.example.org']['errors'] === 0 && $byHost['api.example.org']['max_ms'] >= 5 && $byHost['api.example.org']['route'] === '/symfony');
    check('and a transport failure is a failed call', isset($byHost['down.example.org']) && $byHost['down.example.org']['errors'] === 1);

    // ---- Laravel: Http client events and queues ---------------------------------------------

    class FakeConfig
    {
        public $values;

        public function __construct(array $values)
        {
            $this->values = $values;
        }

        public function get($key, $default = null)
        {
            return array_key_exists($key, $this->values) ? $this->values[$key] : $default;
        }
    }

    class FakeEvents
    {
        public $listeners = array();

        public function listen($event, $listener)
        {
            $this->listeners[$event][] = $listener;
        }

        // As Laravel's until(): the first answer that isn't null.
        public function dispatch($event, $payload)
        {
            foreach (isset($this->listeners[$event]) ? $this->listeners[$event] : array() as $listener) {
                $answer = $listener($payload);
                if ($answer !== null) {
                    return $answer;
                }
            }
            return null;
        }
    }

    class FakeHandler implements Illuminate\Contracts\Debug\ExceptionHandler
    {
        public function reportable(callable $fn)
        {
        }
    }

    class FakeApp implements ArrayAccess
    {
        public $items;
        public $made = array();

        public function __construct(array $items)
        {
            $this->items = $items;
        }

        public function make($name)
        {
            return $this->made[$name];
        }

        public function runningInConsole()
        {
            return true;
        }

        #[\ReturnTypeWillChange]
        public function offsetGet($key)
        {
            return $this->items[$key];
        }

        public function offsetExists($key): bool
        {
            return isset($this->items[$key]);
        }

        public function offsetSet($key, $value): void
        {
        }

        public function offsetUnset($key): void
        {
        }
    }

    class FakeHttpRequest
    {
        private $method;
        private $url;

        public function __construct($method, $url)
        {
            $this->method = $method;
            $this->url = $url;
        }

        public function method()
        {
            return $this->method;
        }

        public function url()
        {
            return $this->url;
        }
    }

    class FakeHttpResponse
    {
        private $status;

        public function __construct($status)
        {
            $this->status = $status;
        }

        public function status()
        {
            return $this->status;
        }
    }

    // A Laravel 12 queue (pendingSize and the rest) and an older one (size() only).
    class FakeNewQueue
    {
        public function size($queue)
        {
            return 99;
        }

        public function pendingSize($queue)
        {
            return $queue === 'emails' ? 1240 : 0;
        }

        public function delayedSize($queue)
        {
            return 12;
        }

        public function reservedSize($queue)
        {
            return 4;
        }

        public function creationTimeOfOldestPendingJob($queue)
        {
            return time() - 610;
        }
    }

    class FakeOldQueue
    {
        public function size($queue)
        {
            return 7;
        }
    }

    class FakeQueueManager
    {
        public function connection($name)
        {
            if ($name === 'broken') {
                throw new RuntimeException('Connection refused');
            }
            return $name === 'redis' ? new FakeNewQueue() : new FakeOldQueue();
        }
    }

    class FakeFailer
    {
        public function count($connection = null, $queue = null)
        {
            return $queue === 'emails' ? 3 : 0;
        }
    }

    class FakeJob
    {
        public $queue;
        private $released;
        private $failed;

        public function __construct($queue, $released = false, $failed = false)
        {
            $this->queue = $queue;
            $this->released = $released;
            $this->failed = $failed;
        }

        public function hasFailed()
        {
            return $this->failed;
        }

        public function getQueue()
        {
            return $this->queue;
        }

        public function isReleased()
        {
            return $this->released;
        }

        public function resolveName()
        {
            return 'App\\Jobs\\SendEmail';
        }
    }

    function config_path($path = '')
    {
        return $path;
    }

    $laravel = hold(platformAt(storeOf('laravel'), array('platform' => 'laravel')));
    $events = new FakeEvents();
    $app = new FakeApp(array(
        'events' => $events,
        'queue' => new FakeQueueManager(),
        'queue.failer' => new FakeFailer(),
        'config' => new FakeConfig(array(
            'analytics-firewall.watch_queues' => 'db:reports,broken:x',
            'queue.default' => 'redis',
            'queue.connections.redis' => array('driver' => 'redis', 'connection' => 'default', 'queue' => 'default'),
            'queue.connections.redis.queue' => 'default',
            'queue.connections.db' => array('driver' => 'database', 'connection' => 'mysql'),
            'queue.connections.broken' => array('driver' => 'beanstalkd', 'host' => 'jobs.internal'),
            'queue.connections.sync' => array('driver' => 'sync'),
            'queue.connections.creds' => array('driver' => 'beanstalkd', 'host' => 'admin:topsecret@Jobs.internal'),
            'database.redis.default' => array('url' => 'redis://app:s3cret@Cache.internal:6380/2'),
            'database.connections.mysql' => array('driver' => 'mysql', 'host' => 'db.internal', 'port' => 3306, 'database' => 'shop',
                'username' => 'shop', 'password' => 'hunter2'),
        )),
    ));
    $app->made = array(Platform::class => $laravel, Illuminate\Contracts\Debug\ExceptionHandler::class => new FakeHandler());
    (new FirewallServiceProvider($app))->boot();

    $laravel->beginRequest();
    $laravel->setRoute('/laravel');
    $sending = new FakeHttpRequest('GET', 'https://api.github.com/repos/x/y?token=abc');
    $events->dispatch('Illuminate\\Http\\Client\\Events\\RequestSending', (object) array('request' => $sending));
    usleep(10000);
    $events->dispatch('Illuminate\\Http\\Client\\Events\\ResponseReceived', (object) array('request' => $sending, 'response' => new FakeHttpResponse(200)));
    // ConnectionFailed hands a request of its own: found by method and address.
    $events->dispatch('Illuminate\\Http\\Client\\Events\\RequestSending', (object) array('request' => new FakeHttpRequest('POST', 'https://hooks.example.com/x')));
    $events->dispatch('Illuminate\\Http\\Client\\Events\\ConnectionFailed', (object) array('request' => new FakeHttpRequest('POST', 'https://hooks.example.com/x')));
    // An answer whose sending wasn't seen isn't timed.
    $events->dispatch('Illuminate\\Http\\Client\\Events\\ResponseReceived', (object) array('request' => new FakeHttpRequest('GET', 'https://unseen.example.com/'), 'response' => new FakeHttpResponse(200)));
    $laravel->recordAndSend();
    flushAll($laravel);
    $byHost = array();
    foreach (rowsOf(sent($laravel, 'queries', '/events/server-calls')) as $row) {
        $byHost[$row['host']] = $row;
    }
    check('Laravel\'s Http calls are timed from RequestSending to ResponseReceived', isset($byHost['api.github.com'])
        && $byHost['api.github.com']['max_ms'] >= 5 && $byHost['api.github.com']['route'] === '/laravel' && $byHost['api.github.com']['errors'] === 0);
    check('ConnectionFailed is a failed call', isset($byHost['hooks.example.com']) && $byHost['hooks.example.com']['errors'] === 1);
    check('an answer to a call not seen sent isn\'t timed', !isset($byHost['unseen.example.com']));

    // Queues. Jobs added from a request (before the worker loops) and from the worker.
    $queued = function ($connection, $queue) use ($events) {
        $events->dispatch('Illuminate\\Queue\\Events\\JobQueued', (object) array('connectionName' => $connection, 'queue' => $queue, 'job' => new FakeJob($queue)));
    };
    $queued('redis', 'emails');
    $queued('redis', 'emails');
    $queued('sync', 'emails');
    $answer = $events->dispatch('Illuminate\\Queue\\Events\\Looping', (object) array('connectionName' => 'redis', 'queue' => 'default,emails'));
    check('the Looping listener lets the worker go on', $answer === null);
    $spool = $laravel->core()->dir() . '/queues.jsonl';
    check('the reading of this minute waits for the minute to end', is_file($spool) && count(file($spool, FILE_SKIP_EMPTY_LINES)) === 1
        && !sent($laravel, 'queues', '/events/server-queues'));
    $queued('redis', 'emails');
    $events->dispatch('Illuminate\\Queue\\Events\\JobProcessed', (object) array('connectionName' => 'redis', 'job' => new FakeJob('emails')));
    $events->dispatch('Illuminate\\Queue\\Events\\JobProcessed', (object) array('connectionName' => 'redis', 'job' => new FakeJob('emails', true)));
    $events->dispatch('Illuminate\\Queue\\Events\\JobFailed', (object) array('connectionName' => 'redis', 'job' => new FakeJob('emails')));
    // A job that called fail() itself and returned: JobFailed, then JobProcessed.
    $selfFailed = new FakeJob('emails', false, true);
    $events->dispatch('Illuminate\\Queue\\Events\\JobFailed', (object) array('connectionName' => 'redis', 'job' => $selfFailed));
    $events->dispatch('Illuminate\\Queue\\Events\\JobProcessed', (object) array('connectionName' => 'redis', 'job' => $selfFailed));
    $events->dispatch('Illuminate\\Queue\\Events\\Looping', (object) array('connectionName' => 'redis', 'queue' => 'default,emails'));
    check('once a minute at most', count(file($spool, FILE_SKIP_EMPTY_LINES)) === 1);
    $laravel->module('queues')->save();
    $laravel->module('queues')->flush(true);
    $bodies = sent($laravel, 'queues', '/events/server-queues');
    $rows = array();
    foreach (rowsOf($bodies) as $row) {
        $rows[$row['broker'] . ' ' . $row['queue']] = $row;
    }
    $emails = isset($rows['cache.internal:6380/2 emails']) ? $rows['cache.internal:6380/2 emails'] : null;
    check('the broker is host, port and database, never the user or password', $emails !== null
        && strpos(json_encode($bodies), 's3cret') === false && strpos(json_encode($bodies), 'hunter2') === false);
    check('the gauges from Laravel 12\'s queue', $emails !== null && $emails['system'] === 'laravel' && $emails['waiting'] === 1240
        && $emails['running'] === 4 && $emails['delayed'] === 12 && $emails['failed'] === 3 && $emails['oldest_s'] >= 609 && $emails['oldest_s'] <= 612);
    check('added and finished are this server\'s counts: a released job isn\'t finished, a failed one is', $emails !== null
        && $emails['added'] === 3 && $emails['finished'] === 3 && $emails['shared'] === false);
    check('a job that failed itself is finished once, not twice', $emails !== null && $emails['finished'] === 3);
    check('a host written with its user and password keeps only the host', (new \AnalyticsPlatform\Laravel\QueueWatch($app))->brokerOf('creds') === 'jobs.internal:11300');
    $tricky = new FakeConfig(array(
        'queue.connections.hash' => array('driver' => 'redis', 'connection' => 'hash'),
        'database.redis.hash' => array('url' => 'redis://app:8812#Kx9@cache.internal:6379/0', 'host' => 'cache.internal'),
        'queue.connections.query' => array('driver' => 'redis', 'connection' => 'query'),
        'database.redis.query' => array('url' => 'redis://cache.internal:6379/1?password=hunter2'),
        'queue.connections.v6' => array('driver' => 'redis', 'connection' => 'v6'),
        'database.redis.v6' => array('host' => '::1', 'port' => 6380),
        'queue.connections.sock' => array('driver' => 'redis', 'connection' => 'sock'),
        'database.redis.sock' => array('url' => 'unix:///var/run/redis/redis.sock'),
    ));
    $trickyWatch = new \AnalyticsPlatform\Laravel\QueueWatch(array('config' => $tricky));
    check('a password parse_url can\'t read as one (an unencoded "#") never becomes the host or port',
        $trickyWatch->brokerOf('hash') === 'cache.internal:6379');
    check('a url\'s query is never read', $trickyWatch->brokerOf('query') === 'cache.internal:6379/1');
    check('an IPv6 host in brackets, a unix socket by its file', $trickyWatch->brokerOf('v6') === '[::1]:6380'
        && $trickyWatch->brokerOf('sock') === 'redis.sock');
    check('an empty queue\'s oldest is 0', isset($rows['cache.internal:6380/2 default']) && $rows['cache.internal:6380/2 default']['waiting'] === 0
        && $rows['cache.internal:6380/2 default']['oldest_s'] === 0 && $rows['cache.internal:6380/2 default']['finished'] === 0);
    $reports = isset($rows['db.internal:3306/shop reports']) ? $rows['db.internal:3306/shop reports'] : null;
    check('a watched queue on an older Laravel: size(), and what it can\'t say is null', $reports !== null && $reports['waiting'] === 7
        && $reports['running'] === null && $reports['delayed'] === null && $reports['oldest_s'] === null && $reports['failed'] === 0
        && $reports['finished'] === null);
    check('a queue that couldn\'t be read is a gap, not a zero', !isset($rows['jobs.internal:11300 x']));
    check('the sync driver has no queue', !array_filter(array_keys($rows), function ($key) {
        return strpos($key, 'sync') !== false;
    }));
    check('each batch names its sender', $bodies && preg_match('/^[a-f0-9]{16}$/', $bodies[0]['sender']) && $bodies[0]['server_name'] === 'web-1');
    check('the reading\'s minute', $emails !== null && preg_match('/^\d{4}-\d\d-\d\dT\d\d:\d\d:00\.000Z$/', $emails['minute']));

    // Two readings of one minute: the largest gauge, the counts summed.
    $merge = hold(platformAt(storeOf('merge')));
    $queues = $merge->module('queues');
    $queues->count('laravel', 'r:6379/0', 'q', 2, 1);
    $queues->record(array(array('system' => 'laravel', 'broker' => 'r:6379/0', 'queue' => 'q', 'waiting' => 10, 'running' => 2)));
    $queues->count('laravel', 'r:6379/0', 'q', 5, 0);
    $queues->record(array(array('system' => 'laravel', 'broker' => 'r:6379/0', 'queue' => 'q', 'waiting' => 4, 'running' => 3)));
    $queues->flush(true);
    $merged = rowsOf(sent($merge, 'queues', '/events/server-queues'));
    check('two readings of a minute: the largest of each gauge, the counts summed', count($merged) === 1 && $merged[0]['waiting'] === 10
        && $merged[0]['running'] === 3 && $merged[0]['added'] === 7 && $merged[0]['finished'] === 1 && $merged[0]['delayed'] === null);

    // ---- WordPress: pre_http_request to http_api_debug ------------------------------------------

    $plugin = __DIR__ . '/../../wordpress-plugin/site-analytics/site-analytics.php';
    if (is_file($plugin) && preg_match('/function site_analytics_calls_started\(.*?\n\}, 10, 5\);\n/s', (string) file_get_contents($plugin), $code)) {
        $hooks = array();
        function add_filter($name, $fn, $priority = 10, $args = 1)
        {
            $GLOBALS['hooks'][$name] = array($fn, $priority);
        }
        function add_action($name, $fn, $priority = 10, $args = 1)
        {
            $GLOBALS['hooks'][$name] = array($fn, $priority);
        }
        function is_wp_error($thing)
        {
            return $thing === 'error';
        }
        function wp_remote_retrieve_response_code($response)
        {
            return $response['response']['code'];
        }
        $wordpress = hold(platformAt(storeOf('wordpress'), array('platform' => 'wordpress')));
        function site_analytics_platform()
        {
            return $GLOBALS['wordpress'];
        }
        eval($code[0]);
        $wordpress->beginRequest();
        $wordpress->setRoute('/:post');
        list($pre, $priority) = $hooks['pre_http_request'];
        $debug = $hooks['http_api_debug'][0];
        $args = array('method' => 'GET', 'blocking' => true);
        check('pre_http_request runs last and hands its value back', $priority === PHP_INT_MAX && $pre(false, $args, 'https://api.wordpress.org/x') === false
            && $pre('answered', $args, 'https://cached.example.com/') === 'answered');
        usleep(10000);
        $debug(array('response' => array('code' => 200)), 'response', 'Requests', $args, 'https://api.wordpress.org/x');
        $pre(false, array('method' => 'POST', 'blocking' => true), 'https://down.example.com/');
        $debug('error', 'response', 'Requests', array('method' => 'POST', 'blocking' => true), 'https://down.example.com/');
        $pre(false, array('method' => 'POST', 'blocking' => false), 'https://fire.example.com/');
        $debug(array('response' => array('code' => false)), 'response', 'Requests', array('method' => 'POST', 'blocking' => false), 'https://fire.example.com/');
        $debug(array('response' => array('code' => 200)), 'response', 'Requests', $args, 'https://cached.example.com/');
        $own = array('method' => 'GET', 'blocking' => true, 'site_analytics_own' => true);
        $pre(false, $own, 'https://own.example.com/px/s.js');
        $debug(array('response' => array('code' => 200)), 'response', 'Requests', $own, 'https://own.example.com/px/s.js');
        $wordpress->recordAndSend();
        flushAll($wordpress);
        $byHost = array();
        foreach (rowsOf(sent($wordpress, 'queries', '/events/server-calls')) as $row) {
            $byHost[$row['host']] = $row;
        }
        check('WordPress\'s calls are timed by host', isset($byHost['api.wordpress.org']) && $byHost['api.wordpress.org']['max_ms'] >= 5
            && $byHost['api.wordpress.org']['route'] === '/:post');
        check('a WP_Error is a failed call', isset($byHost['down.example.com']) && $byHost['down.example.com']['errors'] === 1);
        check('a call that doesn\'t wait, or one another filter answered, isn\'t timed', !isset($byHost['fire.example.com']) && !isset($byHost['cached.example.com']));
        check('the plugin\'s own check of its proxy isn\'t a call of the site\'s', !isset($byHost['own.example.com']));
        cleanUp(storeOf('wordpress'));
    } else {
        echo "SKIP: the WordPress plugin is not alongside this package\n";
    }

    // ---- ClickHouse (smi2/phpclickhouse) ----------------------------------------------------

    class FakeCurlResponse
    {
        public function total_time()
        {
            return 0.012;
        }
    }

    class FakeStatement
    {
        public $error;

        public function __construct($error)
        {
            $this->error = $error;
        }

        public function isError()
        {
            return $this->error;
        }

        public function response()
        {
            return new FakeCurlResponse();
        }
    }

    class FakeClickHouse
    {
        public $db = 'default';

        public function select($sql, $bindings = array())
        {
            return new FakeStatement(strpos($sql, 'missing') !== false);
        }

        public function write($sql, $bindings = array(), $exception = true)
        {
            if (strpos($sql, 'bad') !== false) {
                throw new RuntimeException('Syntax error');
            }
            return new FakeStatement(false);
        }

        public function insert($table, $values, $columns = array())
        {
            return new FakeStatement(false);
        }

        public function selectAsync($sql, $bindings = array())
        {
            return new FakeStatement(false);
        }

        public function executeAsync()
        {
            return true;
        }

        public function database($name)
        {
            $this->db = $name;
            return $this;
        }

        public function ping()
        {
            return true;
        }
    }

    $ch = hold(platformAt(storeOf('clickhouse')));
    $ch->beginRequest();
    $ch->setRoute('/stats');
    $db = new TimedClickHouse(new FakeClickHouse());
    $db->select("SELECT count() FROM events WHERE site = 'abc' AND day >= :from", array('from' => '2026-11-01'));
    $db->select('SELECT * FROM missing');
    $db->write('ALTER TABLE events DELETE WHERE day < 20260101');
    try {
        $db->write('bad sql');
    } catch (RuntimeException $e) {
        // counted as failed
    }
    $db->insert('events', array(array('abc', 'a@b.c'), array('def', 'x@y.z')), array('site', 'email'));
    $db->selectAsync('SELECT 1 AS a');
    $db->selectAsync('SELECT 2 AS b');
    $db->executeAsync();
    $chained = $db->database('analytics');
    check('a method that hands back the client hands back the timer', $chained === $db && $db->client()->db === 'analytics' && $db->ping() === true);
    $ch->recordAndSend();
    flushAll($ch);
    $byStatement = array();
    foreach (rowsOf(sent($ch, 'queries', '/events/server-queries')) as $row) {
        $byStatement[$row['statement']] = $row;
    }
    check('ClickHouse queries are timed as clickhouse, values out, placeholders kept', isset($byStatement['SELECT count() FROM events WHERE site = ? AND day >= :from'])
        && $byStatement['SELECT count() FROM events WHERE site = ? AND day >= :from']['db'] === 'clickhouse'
        && $byStatement['SELECT count() FROM events WHERE site = ? AND day >= :from']['route'] === '/stats');
    check('a select the server refused counts as failed', isset($byStatement['SELECT * FROM missing']) && $byStatement['SELECT * FROM missing']['errors'] === 1);
    check('a write that threw counts as failed', isset($byStatement['bad sql']) && $byStatement['bad sql']['errors'] === 1
        && $byStatement['ALTER TABLE events DELETE WHERE day < ?']['errors'] === 0);
    check('an insert is its table and columns, never its values', isset($byStatement['INSERT INTO events (site, email) VALUES (?)'])
        && strpos(json_encode(array_keys($byStatement)), 'a@b.c') === false);
    check('async selects are counted once run, by their own transfer time', isset($byStatement['SELECT ? AS a'], $byStatement['SELECT ? AS b'])
        && $byStatement['SELECT ? AS a']['max_ms'] == 12.0);

    foreach (array('off', 'main', 'quiet', 'cli', 'jobs', 'fold', 'guzzle', 'symfony', 'laravel', 'merge', 'clickhouse') as $name) {
        cleanUp(storeOf($name));
    }

    echo ($failed ? "FAILED" : "OK") . ": $checked checks, $failed failed\n";
    exit($failed ? 1 : 0);
}
