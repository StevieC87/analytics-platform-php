<?php
// Database query timings (sdk/protocols/queries.md): every shared case in
// sdk/protocols/query-cases.json normalized character for character as the
// collector's queryText.js does; each query added to the request it ran in,
// the job it ran in, or JOB "(background)"; the caps (50 a request, 200 and
// 300 a minute); the payload sent; TimedPdo against a real SQLite database;
// and the Laravel, Symfony (Doctrine) and WordPress hooks against stand-ins
// for the few classes they name. The collector is a closed port, so what
// would be sent waits in the retry spool, where this reads it.
//
//   php test/QueriesTest.php

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

namespace Illuminate\Database {
    class QueryException extends \RuntimeException
    {
        public $connectionName;
        private $sql;

        public function __construct($connectionName, $sql)
        {
            parent::__construct('failed');
            $this->connectionName = $connectionName;
            $this->sql = $sql;
        }

        public function getSql()
        {
            return $this->sql;
        }
    }
}

namespace Doctrine\DBAL {
    interface Driver
    {
        public function connect(array $params);
    }
}

namespace Doctrine\DBAL\Driver {
    interface Middleware
    {
        public function wrap(\Doctrine\DBAL\Driver $driver): \Doctrine\DBAL\Driver;
    }
    interface Connection
    {
    }
    interface Statement
    {
    }
    interface Result
    {
    }
}

// DBAL 4's signatures (exec(): int|string, execute() without arguments).
namespace Doctrine\DBAL\Driver\Middleware {
    abstract class AbstractDriverMiddleware implements \Doctrine\DBAL\Driver
    {
        private $wrapped;

        public function __construct(\Doctrine\DBAL\Driver $wrapped)
        {
            $this->wrapped = $wrapped;
        }

        public function connect(array $params): \Doctrine\DBAL\Driver\Connection
        {
            return $this->wrapped->connect($params);
        }
    }
    abstract class AbstractConnectionMiddleware implements \Doctrine\DBAL\Driver\Connection
    {
        private $wrapped;

        public function __construct(\Doctrine\DBAL\Driver\Connection $wrapped)
        {
            $this->wrapped = $wrapped;
        }

        public function prepare(string $sql): \Doctrine\DBAL\Driver\Statement
        {
            return $this->wrapped->prepare($sql);
        }

        public function query(string $sql): \Doctrine\DBAL\Driver\Result
        {
            return $this->wrapped->query($sql);
        }

        public function exec(string $sql): int|string
        {
            return $this->wrapped->exec($sql);
        }
    }
    abstract class AbstractStatementMiddleware implements \Doctrine\DBAL\Driver\Statement
    {
        private $wrapped;

        public function __construct(\Doctrine\DBAL\Driver\Statement $wrapped)
        {
            $this->wrapped = $wrapped;
        }

        public function execute(): \Doctrine\DBAL\Driver\Result
        {
            return $this->wrapped->execute();
        }
    }
}

namespace {
    foreach (glob(__DIR__ . '/../src/*.php') as $file) {
        require_once $file;
    }
    require_once __DIR__ . '/../src/Laravel/FirewallServiceProvider.php';
    require_once __DIR__ . '/../src/Symfony/QueryMiddleware.php';

    use AnalyticsPlatform\Laravel\FirewallServiceProvider;
    use AnalyticsPlatform\Platform;
    use AnalyticsPlatform\Queries;
    use AnalyticsPlatform\Symfony\QueryMiddleware;
    use AnalyticsPlatform\TimedPdo;

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

    // ---- Normalizing: the shared cases ---------------------------------------------

    $cases = json_decode((string) file_get_contents(__DIR__ . '/../../protocols/query-cases.json'), true);
    check('the shared cases load', is_array($cases) && !empty($cases['cases']));
    check('the cases agree on the length', $cases['max_statement'] === Queries::MAX_STATEMENT);
    foreach ($cases['cases'] as $i => $case) {
        $got = Queries::normalize($case['statement'], $case['db']);
        check("case $i ({$case['db']}): " . substr($case['statement'], 0, 60) . ' gives ' . substr($got, 0, 60), $got === $case['expected']);
    }
    // Beyond the shared cases: the parts of JavaScript's rule PHP does differently on its own.
    check('integer keys come first, as a JavaScript object has them', Queries::normalize('find t {"b":1,"10":2,"2":3,"01":4}', 'mongodb') === 'find t {"2":"?","10":"?","b":"?","01":"?"}');
    check('{} and [] stay apart', Queries::normalize('find t {"a":{},"b":[]}', 'mongodb') === 'find t {"a":{},"b":[]}');
    check('a tab after the command is no statement at all', Queries::normalize("find\tusers", 'mongodb') === '');
    check('a newline after the collection drops the collection', Queries::normalize("find users\n{}", 'mongodb') === 'find');
    check('a no-break space is whitespace', Queries::normalize("SELECT\u{A0}1", 'postgresql') === 'SELECT ?');
    check('and so are U+FEFF and U+2028, trimmed too', Queries::normalize("SELECT\u{FEFF} 1 \u{2028}", 'x') === 'SELECT ?');
    check('"__proto__" goes, as it does from a JavaScript object', Queries::normalize('find t {"__proto__":{"x":1},"a":1}', 'mongodb') === 'find t {"a":"?"}');
    check('an array of different shapes keeps each', Queries::normalize('find t [1,"a",{}]', 'mongodb') === 'find t ["?","?",{}]');
    check('bytes that are not UTF-8 are copied, not a failure', Queries::normalize("SELECT 'a' AS \xFF", 'mysql') === "SELECT ? AS \xFF");
    check('not a string is nothing', Queries::normalize(null, 'mysql') === '');
    check('a driver name maps to the database', Queries::databaseOfDriver('pdo_pgsql') === 'postgresql' && Queries::databaseOfDriver('sqlsrv') === 'mssql'
        && Queries::databaseOfDriver('firebird') === 'other');
    check('a Mongo command is written as the protocol says', Queries::mongoText('find', (object) array('find' => 'users', 'filter' => (object) array('email' => 'a@b.c'))) === 'find users {"email":"a@b.c"}');
    check('a delete names its first filter', Queries::mongoText('delete', (object) array('delete' => 'users', 'deletes' => array((object) array('q' => (object) array('a' => 1)))))
        === 'delete users {"a":1}');
    check('connection chatter is never recorded', Queries::mongoText('hello', (object) array('hello' => 1)) === '');

    // ---- Recording and sending --------------------------------------------------------

    function storeOf($name)
    {
        return sys_get_temp_dir() . '/analytics-queries-test-' . $name . '-' . getmypid();
    }

    function platformAt($store, array $more = array())
    {
        return new Platform($more + array('site_id' => 'a1b2c3d4e5f6a1b2c3d4e5f6', 'secret' => 'the-site-secret',
            'endpoint' => 'http://127.0.0.1:9', 'storage' => $store, 'server_name' => 'web-1',
            'firewall' => false, 'proxy' => false, 'inventory' => false, 'resources' => false, 'crawlers' => false));
    }

    // The lines waiting in queries.jsonl.
    function spooled(Platform $platform)
    {
        $file = $platform->core()->dir() . '/queries.jsonl';
        $lines = is_file($file) ? file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : array();
        return array_map(function ($line) {
            return json_decode($line, true);
        }, $lines);
    }

    // What flush() would have sent: the bodies kept to send again.
    function sent(Platform $platform)
    {
        $file = $platform->core()->dir() . '/queries.retry.jsonl';
        $bodies = array();
        foreach (is_file($file) ? file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : array() as $line) {
            $bodies[] = json_decode($line, true);
        }
        return $bodies;
    }

    // Nothing is sent until flush(true): the last send was just now.
    function hold(Platform $platform)
    {
        $platform->core()->ensureDir();
        touch($platform->core()->dir() . '/queries.lock');
        return $platform;
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

    check('queries: false leaves it out', !in_array('queries', platformAt(storeOf('off'), array('queries' => false))->modules(), true));
    check('and so does performance: false', !in_array('queries', platformAt(storeOf('off'), array('performance' => false))->modules(), true));

    // Queries timed before any Platform exists (WordPress's drop-in) are the
    // first request's.
    Queries::report('mysql', "SELECT option_value FROM wp_options WHERE option_name = 'siteurl'", 2.0);
    $platform = hold(platformAt(storeOf('main')));
    check('the queries module rides on performance', in_array('queries', $platform->modules(), true));
    $platform->setRoute('/early');
    $platform->recordAndSend();
    $lines = spooled($platform);
    check('a query from before the Platform is in the request it ran in', count($lines) === 1 && $lines[0]['r'] === '/early'
        && $lines[0]['q'][0][1] === 'SELECT option_value FROM wp_options WHERE option_name = ?');

    // A web request (the test runs on the command line, so a worker's next request).
    $platform->beginRequest();
    $platform->setRoute('/orders/{id}');
    for ($i = 1; $i <= 40; $i++) {
        $platform->recordQuery('postgresql', "SELECT * FROM orders WHERE id = $i", 3.0);
    }
    $platform->recordQuery('postgresql', "UPDATE orders SET paid = true WHERE id = 7", 120.0, true);
    $platform->recordQuery('postgresql', "  ", 1.0);
    $platform->recordAndSend();
    $lines = spooled($platform);
    check('one line for the request', count($lines) === 2);
    $line = $lines[1];
    check('under the method and route Server speed recorded', $line['m'] === 'GET' && $line['r'] === '/orders/{id}');
    $byStatement = array();
    foreach ($line['q'] as $q) {
        $byStatement[$q[1]] = $q;
    }
    $select = $byStatement['SELECT * FROM orders WHERE id = ?'];
    check('forty runs of one query are one entry', count($line['q']) === 2 && $select[2] === 40 && $select[3] === 0 && $select[4] == 120.0 && $select[6][0] === 40);
    $update = $byStatement['UPDATE orders SET paid = true WHERE id = ?'];
    check('a failed one counts as run and failed, in its bucket', $update[2] === 1 && $update[3] === 1 && $update[5] == 120.0 && $update[6][5] === 1);
    check('an empty statement is not recorded', !isset($byStatement['']));

    // The next request starts afresh, and past 50 statements new ones are "(other)".
    $platform->beginRequest();
    $platform->setRoute('/search');
    for ($i = 0; $i < 60; $i++) {
        $platform->recordQuery('mysql', "SELECT * FROM t$i", 1.0);
    }
    $platform->recordAndSend();
    $lines = spooled($platform);
    $other = array_values(array_filter($lines[2]['q'], function ($q) {
        return $q[1] === '(other)';
    }));
    check('fifty statements and one "(other)" a request', count($lines[2]['q']) === 51 && count($other) === 1 && $other[0][2] === 10);

    // A job's queries are its own, under its JOB row.
    $platform->job('send-receipts', function () use ($platform) {
        $platform->recordQuery('mysql', 'DELETE FROM sessions WHERE expires < 1700000000', 4.0);
    });
    $jobLines = spooled($platform);
    $jobLine = end($jobLines);
    $timed = array_map(function ($line) {
        return json_decode($line, true);
    }, file($platform->core()->dir() . '/requests.jsonl', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES));
    $timedJob = end($timed);
    check('the job\'s queries are filed under the minute, method and route Server speed recorded the run with',
        $timedJob['m'] === 'JOB' && $jobLine['t'] === $timedJob['t'] && $jobLine['m'] === $timedJob['m'] && $jobLine['r'] === $timedJob['r']);

    // Outside a request or job: background.
    $cli = platformAt(storeOf('cli'));
    $cli->recordQuery('sqlite', 'VACUUM', 9.0);
    // The end of the script: written out, and sent from the command line.
    $cli->module('queries')->onShutdown();
    $background = sent($cli);
    $row = isset($background[0]['body']['rows'][0]) ? $background[0]['body']['rows'][0] : array();
    check('a query outside a request is JOB (background), sent as the script ends', count($background) === 1
        && $row['method'] === 'JOB' && $row['route'] === '(background)' && $row['statement'] === 'VACUUM' && $row['db'] === 'sqlite');

    // A job's lines are written as it ends; flush(true) is the minute passing.
    check('the job has its own line', count(spooled($platform)) === 4);
    $platform->module('queries')->flush(true);

    // ---- The payload --------------------------------------------------------------------

    $bodies = sent($platform);
    check('sent once, to /events/server-queries, with the bearer secret', count($bodies) === 1 && $bodies[0]['path'] === '/events/server-queries' && $bodies[0]['auth'] === 'bearer');
    $body = $bodies[0]['body'];
    check('the body names the site, the server and PHP', $body['site_id'] === 'a1b2c3d4e5f6a1b2c3d4e5f6' && $body['server_name'] === 'web-1'
        && strpos($body['runtime'], 'PHP ') === 0 && !isset($body['sitesecret']));
    $rows = array();
    foreach ($body['rows'] as $row) {
        $rows[$row['route'] . ' ' . $row['statement']] = $row;
    }
    $row = isset($rows['/orders/{id} SELECT * FROM orders WHERE id = ?']) ? $rows['/orders/{id} SELECT * FROM orders WHERE id = ?'] : null;
    check('a row as the protocol has it', $row !== null && preg_match('/^\d{4}-\d\d-\d\dT\d\d:\d\d:00\.000Z$/', $row['minute'])
        && $row['method'] === 'GET' && $row['db'] === 'postgresql' && $row['count'] === 40 && $row['errors'] === 0
        && $row['sum_ms'] == 120.0 && $row['max_ms'] == 3.0 && count($row['buckets']) === 12);
    check('the early query is in its request\'s row', isset($rows['/early SELECT option_value FROM wp_options WHERE option_name = ?']));
    check('the job\'s query under the job', isset($rows['/(job) send-receipts DELETE FROM sessions WHERE expires < ?'])
        && $rows['/(job) send-receipts DELETE FROM sessions WHERE expires < ?']['method'] === 'JOB');
    check('nothing is left waiting', spooled($platform) === array());

    // The minute's caps: past 200 keys "(other)", past 300 nothing new.
    // Four routes of 50 statements fill 200 keys; each of 110 more routes
    // gets its own "(other)" until 300, and the last 10 nothing.
    $caps = hold(platformAt(storeOf('caps')));
    for ($r = 0; $r < 114; $r++) {
        $caps->beginRequest();
        $caps->setRoute('/r' . $r);
        for ($i = 0; $i < ($r < 4 ? 50 : 1); $i++) {
            $caps->recordQuery('mysql', "SELECT * FROM t{$r}_$i", 1.0);
        }
        $caps->recordAndSend();
    }
    $caps->module('queries')->flush(true);
    $rows = array();
    foreach (sent($caps) as $batch) {
        $rows = array_merge($rows, $batch['body']['rows']);
    }
    $others = array_filter($rows, function ($row) {
        return $row['statement'] === '(other)';
    });
    check('200 statements, then "(other)" per route, then nothing new past 300', count($rows) === 300 && count($others) === 100);

    // ---- TimedPdo, against a real SQLite database -------------------------------------

    $platform = hold(platformAt(storeOf('pdo')));
    $platform->beginRequest();
    $platform->setRoute('/pdo');
    $pdo = new TimedPdo('sqlite::memory:');
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->exec('CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT)');
    $insert = $pdo->prepare('INSERT INTO users (email) VALUES (?)');
    $insert->execute(array('ana@example.com'));
    $insert->execute(array('bob@example.com'));
    $count = $pdo->query("SELECT count(*) FROM users WHERE email LIKE '%example%'")->fetchColumn();
    try {
        $pdo->exec('SELECT * FROM missing');
    } catch (PDOException $e) {
        // counted as failed
    }
    $platform->recordAndSend();
    $lines = spooled($platform);
    $pdoLine = end($lines);
    $byStatement = array();
    foreach ($pdoLine['q'] as $q) {
        $byStatement[$q[1]] = $q;
    }
    check('TimedPdo works as PDO', (int) $count === 2 && $pdoLine['r'] === '/pdo');
    check('exec, prepared execute and query are timed, as sqlite', isset($byStatement['CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT)'])
        && $byStatement['INSERT INTO users (email) VALUES (?)'][2] === 2 && $byStatement['INSERT INTO users (email) VALUES (?)'][0] === 'sqlite'
        && isset($byStatement['SELECT count(*) FROM users WHERE email LIKE ?']));
    check('a query that threw counts as failed', $byStatement['SELECT * FROM missing'][3] === 1);

    // ---- Laravel ----------------------------------------------------------------------

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

        public function dispatch($event, $payload)
        {
            foreach (isset($this->listeners[$event]) ? $this->listeners[$event] : array() as $listener) {
                $listener($payload);
            }
        }
    }

    class FakeHandler implements Illuminate\Contracts\Debug\ExceptionHandler
    {
        public $reportable = array();

        public function reportable(callable $fn)
        {
            $this->reportable[] = $fn;
        }

        public function report($error)
        {
            foreach ($this->reportable as $fn) {
                $fn($error);
            }
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

    class FakeConnection
    {
        private $driver;

        public function __construct($driver)
        {
            $this->driver = $driver;
        }

        public function getDriverName()
        {
            return $this->driver;
        }
    }

    function config_path($path = '')
    {
        return $path;
    }

    $laravel = hold(platformAt(storeOf('laravel'), array('platform' => 'laravel')));
    $events = new FakeEvents();
    $handler = new FakeHandler();
    $app = new FakeApp(array(
        'events' => $events,
        'config' => new FakeConfig(array('database.default' => 'pgsql', 'database.connections.pgsql.driver' => 'pgsql')),
    ));
    $app->made = array(Platform::class => $laravel, Illuminate\Contracts\Debug\ExceptionHandler::class => $handler);
    (new FirewallServiceProvider($app))->boot();
    check('the provider listens for queries in a console too', isset($events->listeners['Illuminate\\Database\\Events\\QueryExecuted']));
    $executed = function ($sql, $ms, $driver) use ($events) {
        $events->dispatch('Illuminate\\Database\\Events\\QueryExecuted', (object) array('sql' => $sql, 'time' => $ms, 'connection' => new FakeConnection($driver)));
    };
    $events->dispatch('Laravel\\Octane\\Events\\RequestReceived', null);
    $laravel->setRoute('/users/{user}');
    $executed('select * from "users" where "id" = ? limit 1', 1.5, 'pgsql');
    $executed('{"find":"users"}', 2.0, 'mongodb');
    $handler->report(new Illuminate\Database\QueryException('pgsql', 'insert into "users" ("email") values (?)'));
    $handler->report(new RuntimeException('not a query'));
    $laravel->recordAndSend();
    $lines = spooled($laravel);
    $byStatement = array();
    foreach (isset($lines[0]['q']) ? $lines[0]['q'] : array() as $q) {
        $byStatement[$q[1]] = $q;
    }
    check('QueryExecuted is timed under the request, as postgresql', $lines && $lines[0]['r'] === '/users/{user}'
        && $byStatement['select * from "users" where "id" = ? limit ?'][0] === 'postgresql');
    check('a reported QueryException is a failed query', isset($byStatement['insert into "users" ("email") values (?)'])
        && $byStatement['insert into "users" ("email") values (?)'][3] === 1);
    check('mongodb connections are left to the driver\'s subscriber', count($byStatement) === 2);

    // ---- Symfony: the Doctrine middleware -----------------------------------------------

    class FakeResult implements Doctrine\DBAL\Driver\Result
    {
    }

    class FakeStatement implements Doctrine\DBAL\Driver\Statement
    {
        public function execute()
        {
            return new FakeResult();
        }
    }

    class FakeDriverConnection implements Doctrine\DBAL\Driver\Connection
    {
        public function prepare($sql)
        {
            return new FakeStatement();
        }

        public function query($sql)
        {
            if (strpos($sql, 'missing') !== false) {
                throw new RuntimeException('no such table');
            }
            return new FakeResult();
        }

        public function exec($sql)
        {
            return 3;
        }
    }

    class FakeDriver implements Doctrine\DBAL\Driver
    {
        public function connect(array $params)
        {
            return new FakeDriverConnection();
        }
    }

    $symfony = hold(platformAt(storeOf('symfony'), array('platform' => 'symfony')));
    $symfony->beginRequest();
    $symfony->setRoute('/products/{id}');
    $connection = (new QueryMiddleware($symfony))->wrap(new FakeDriver())->connect(array('driver' => 'pdo_mysql'));
    $connection->prepare('SELECT * FROM product WHERE id = ?')->execute();
    $connection->query("SELECT * FROM product WHERE name = 'lamp'");
    $connection->exec('UPDATE product SET views = views + 1');
    try {
        $connection->query('SELECT * FROM missing');
    } catch (RuntimeException $e) {
        // counted as failed
    }
    $symfony->recordAndSend();
    $lines = spooled($symfony);
    $byStatement = array();
    foreach (isset($lines[0]['q']) ? $lines[0]['q'] : array() as $q) {
        $byStatement[$q[1]] = $q;
    }
    check('Doctrine\'s execute, query and exec are timed, as mysql', count($byStatement) === 4
        && $byStatement['SELECT * FROM product WHERE id = ?'][0] === 'mysql' && isset($byStatement['SELECT * FROM product WHERE name = ?'])
        && isset($byStatement['UPDATE product SET views = views + ?']));
    check('a Doctrine query that threw counts as failed', $byStatement['SELECT * FROM missing'][3] === 1);
    // A TimedPdo under Doctrine leaves the query to the middleware.
    $symfony->beginRequest();
    $inner = new TimedPdo('sqlite::memory:');
    Queries::timed('mysql', 'SELECT 1', function () use ($inner) {
        return $inner->query('SELECT 1');
    });
    $symfony->recordAndSend();
    $lines = spooled($symfony);
    check('two layers count one query once', count($lines[1]['q']) === 1 && $lines[1]['q'][0][0] === 'mysql');

    // ---- WordPress: the db.php drop-in ------------------------------------------------

    $plugin = __DIR__ . '/../../wordpress-plugin/site-analytics/site-analytics.php';
    if (is_file($plugin) && preg_match('/function site_analytics_db_dropin_code\(\)\n\{\n.*?\nPHP;\n\}\n/s', (string) file_get_contents($plugin), $code)) {
        // The plugin's own function, with what it uses of WordPress stood in.
        define('ABSPATH', __DIR__ . '/');
        define('DB_USER', 'wp');
        define('SITE_ANALYTICS_DB_DROPIN_MARK', 'Site Analytics query timing');
        eval(str_replace("__DIR__ . '/lib/Queries.php'", var_export(realpath(__DIR__ . '/../src/Queries.php'), true), $code[0]));
        class wpdb
        {
            public $dbh = true;
            public $user;

            public function __construct($user, $password, $name, $host)
            {
                $this->user = $user;
            }

            public function db_server_info()
            {
                return '5.5.5-10.11.6-MariaDB-0+deb12u1';
            }

            public function query($query)
            {
                return strpos($query, 'missing') === false ? 1 : false;
            }
        }
        $dropin = storeOf('dropin') . '.php';
        file_put_contents($dropin, site_analytics_db_dropin_code());
        check('the drop-in carries the mark the plugin removes it by', strpos((string) file_get_contents($dropin, false, null, 0, 1000), SITE_ANALYTICS_DB_DROPIN_MARK) !== false);
        $wordpress = hold(platformAt(storeOf('wordpress'), array('platform' => 'wordpress')));
        $wordpress->beginRequest();
        $wordpress->setRoute('/:post');
        unset($wpdb);
        (function () use ($dropin) {
            require $dropin;
        })();
        global $wpdb;
        check('the drop-in replaces $wpdb with its own, made as WordPress makes it', $wpdb instanceof Site_Analytics_Timed_wpdb && $wpdb->user === 'wp');
        $wpdb->query("SELECT * FROM wp_posts WHERE ID = 42");
        $wpdb->query('SELECT * FROM missing');
        $wordpress->recordAndSend();
        $lines = spooled($wordpress);
        $byStatement = array();
        foreach (isset($lines[0]['q']) ? $lines[0]['q'] : array() as $q) {
            $byStatement[$q[1]] = $q;
        }
        check('wpdb::query() is timed, as mariadb, failures included', isset($byStatement['SELECT * FROM wp_posts WHERE ID = ?'])
            && $byStatement['SELECT * FROM wp_posts WHERE ID = ?'][0] === 'mariadb' && $byStatement['SELECT * FROM missing'][3] === 1);
        @unlink($dropin);
        cleanUp(storeOf('wordpress'));
    } else {
        echo "SKIP: the WordPress plugin is not alongside this package\n";
    }

    foreach (array('main', 'off', 'cli', 'caps', 'pdo', 'laravel', 'symfony') as $name) {
        cleanUp(storeOf($name));
    }

    echo ($failed ? "FAILED" : "OK") . ": $checked checks, $failed failed\n";
    exit($failed ? 1 : 0);
}
