<?php
// Database queries (protocol in sdk/protocols/queries.md): the half of Server
// speed that says *why* a route is slow. Every query the site's own code runs
// is timed through the database library's public hook, its values taken out
// (normalize(), the collector's queryText.js ported), and added to a small
// map for the request it ran in: per database and statement, how many ran,
// how many failed, their total and slowest time and a count per time bucket.
//
// PHP handles one request per process at a time, so the request's map lives
// here. When the request ends, the performance module records its method and
// route, and the map is written next to them as one line of queries.jsonl;
// once a minute one request adds the lines up per minute, method, route,
// database and statement and sends them to POST /events/server-queries, as
// the performance module does with requests.jsonl. A queue job's queries go
// under the job's own row, and a query outside any request or job (a cron
// script, a worker between jobs) under JOB "(background)".
//
// The hooks, each recording a query once:
// - Laravel: QueryExecuted (DB::listen), in the service provider.
// - Symfony: Doctrine DBAL's middleware (Symfony\QueryMiddleware).
// - Plain PHP: new TimedPdo(...) instead of new PDO(...).
// - MongoDB: the mongodb extension's global command subscriber, on its own
//   whenever the extension is loaded (Laravel's mongodb connections are
//   left to it, so they aren't counted twice).
// - WordPress: the plugin's wp-content/db.php drop-in, else SAVEQUERIES.
// Each reports through Queries::report(), which works before any Platform
// exists (WordPress's drop-in runs before the plugins load): those queries
// wait here for the first one.
//
// No values ever leave the server: literals are replaced by "?" before a
// query is counted, and bound parameters are never read. Rides on the
// performance module's switch; 'queries' => false leaves it out.

namespace AnalyticsPlatform;

class Queries
{
    // Keep in step with Performance::BUCKET_EDGES_MS and the collector
    // (expresscollect/Analytics/serverRequests.js). Copied, not referenced:
    // WordPress's drop-in loads this file before Performance exists.
    const BUCKET_EDGES_MS = array(5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000);
    const FLUSH_EVERY = 60;
    // A request's distinct statements; past it new ones go under "(other)".
    const MAX_PER_REQUEST = 50;
    // Keys in a minute: past MAX_KEYS new statements go under "(other)",
    // past HARD_MAX_KEYS nothing new is kept.
    const MAX_KEYS = 200;
    const HARD_MAX_KEYS = 300;
    const MAX_ROWS = 500;
    const SPOOL_MAX = 5000000; // bytes waiting; more requests' queries aren't recorded
    // A request's line holds up to 50 statements, so a busy site fills the
    // spool far sooner than requests.jsonl: past this it is sent at once
    // rather than at the next minute.
    const SEND_BYTES = 1000000;
    const MAX_STATEMENT = 1000;
    const OTHER = '(other)';
    const BACKGROUND = '(background)';
    const DATABASES = array('postgresql', 'mysql', 'mariadb', 'sqlite', 'mssql', 'oracle', 'mongodb', 'other');
    // Mongo's connection chatter, never a query of the site's.
    const MONGO_CHATTER = array('hello', 'isMaster', 'ismaster', 'ping', 'buildInfo', 'saslStart', 'saslContinue',
        'getMore', 'endSessions', 'killCursors', 'getLastError');

    // The module the hooks report to: the last one built.
    private static $active = null;
    // Queries timed before any module existed, as one request's map.
    private static $early = array();
    // How deep inside a timed call we are: an inner hook (a TimedPdo under
    // Doctrine) leaves the query to the outer one.
    private static $depth = 0;
    private static $mongo = false;
    private static $cache = array();

    private $core;
    private $options;
    private $request = array();
    // The jobs running, innermost last: each its own map.
    private $jobs = array();
    private $background = array();
    private $backgroundMinute = 0;
    private $shutdown = false;
    // Whether a query outside a job belongs to a request: a web server's
    // process, or a worker serving requests once beginRequest() says so.
    private $serving;

    // Options: server_name (default the host name).
    public function __construct(Core $core, array $options = array())
    {
        $this->core = $core;
        $this->options = $options + array('server_name' => function_exists('gethostname') ? gethostname() : '');
        $this->serving = PHP_SAPI !== 'cli' && PHP_SAPI !== 'phpdbg';
        $this->request = self::$early;
        self::$early = array();
        self::$active = $this;
        self::watchMongo();
    }

    // ---- Recording --------------------------------------------------------------

    // What every hook calls: a query that took $ms and threw (or returned
    // false) when $failed.
    public static function report($db, $sql, $ms, $failed = false)
    {
        if (self::$active !== null) {
            self::$active->record($db, $sql, $ms, $failed);
            return;
        }
        try {
            $db = self::databaseOf($db);
            $statement = self::statement($sql, $db);
            if ($statement !== '') {
                self::add(self::$early, $db, $statement, (float) $ms, $failed, self::MAX_PER_REQUEST);
            }
        } catch (\Throwable $e) {
            // never break the query it was told of
        }
    }

    // Runs a query and reports it, for the hooks that run it themselves
    // (TimedPdo, Doctrine's middleware): failed when it threw or returned
    // false (PDO without exceptions). Inside another timed call it only
    // runs: the outer hook reports it.
    public static function timed($db, $sql, callable $run)
    {
        $outer = self::$depth++ === 0;
        $started = microtime(true);
        $failed = true;
        try {
            $result = $run();
            $failed = $result === false;
            return $result;
        } finally {
            self::$depth = max(0, self::$depth - 1);
            if ($outer) {
                self::report($db, $sql, (microtime(true) - $started) * 1000, $failed);
            }
        }
    }

    // Never throws: it runs inside the site's own query call (TimedPdo's
    // finally, Laravel's listener), where a framework's error handler would
    // turn a file warning into an exception thrown at that query.
    public function record($db, $sql, $ms, $failed = false)
    {
        try {
            if (!$this->core->isOn('performance')) {
                return;
            }
            $db = self::databaseOf($db);
            $statement = self::statement($sql, $db);
            if ($statement === '') {
                return;
            }
            $ms = max(0.0, (float) $ms);
            if ($this->jobs) {
                self::add($this->jobs[count($this->jobs) - 1], $db, $statement, $ms, $failed, self::MAX_PER_REQUEST);
            } elseif ($this->serving) {
                self::add($this->request, $db, $statement, $ms, $failed, self::MAX_PER_REQUEST);
            } else {
                $this->addBackground($db, $statement, $ms, $failed);
            }
        } catch (\Throwable $e) {
            // not counted
        }
    }

    // A worker that serves many requests from one process (Octane,
    // RoadRunner, FrankenPHP) starting the next one: nothing of the last is
    // kept, and queries outside a job belong to requests from now on.
    public function beginRequest()
    {
        $this->request = array();
        $this->serving = true;
    }

    // The request ended. $recorded: the method, route and time the
    // performance module recorded it under (Performance::recordRequest), so
    // the dashboard can join the two; null when it recorded nothing (the
    // visitor went away), and the queries go with it; false when the request
    // isn't one it times (WordPress's cron), and they count as background.
    public function endRequest($recorded)
    {
        $map = $this->request;
        $this->request = array();
        $this->file($map, $recorded);
    }

    public function startJob()
    {
        $this->jobs[] = array();
    }

    // The job ended. $recorded: what the performance module recorded the run
    // under (Performance::recordJob), as endRequest's.
    public function endJob($recorded)
    {
        if (!$this->jobs) {
            return;
        }
        $this->file(array_pop($this->jobs), $recorded);
    }

    // A finished request's or job's queries, under what it was recorded as.
    private function file(array $map, $recorded)
    {
        if (!$map) {
            return;
        }
        if ($recorded === false) {
            foreach ($map as $row) {
                $this->mergeBackground($row);
            }
            $this->saveBackground();
        } elseif (is_array($recorded) && isset($recorded['t'], $recorded['m'], $recorded['r'])) {
            $this->save($recorded['t'], $recorded['m'], $recorded['r'], $map);
        }
    }

    private static function add(array &$map, $db, $statement, $ms, $failed, $cap)
    {
        $key = $db . "\0" . $statement;
        if (!isset($map[$key]) && count($map) >= $cap) {
            $statement = self::OTHER;
            $key = $db . "\0" . $statement;
        }
        if (!isset($map[$key])) {
            $map[$key] = array($db, $statement, 0, 0, 0.0, 0.0, array_fill(0, count(self::BUCKET_EDGES_MS) + 1, 0));
        }
        $map[$key][2]++;
        if ($failed) {
            $map[$key][3]++;
        }
        $map[$key][4] += $ms;
        if ($ms > $map[$key][5]) {
            $map[$key][5] = $ms;
        }
        $map[$key][6][self::bucketOf($ms)]++;
    }

    // Outside a request or job: kept per minute in memory, written out when
    // the minute changes and at the end of the script.
    private function addBackground($db, $statement, $ms, $failed)
    {
        $minute = (int) (floor(time() / 60) * 60);
        if ($this->background && $minute !== $this->backgroundMinute) {
            $this->saveBackground();
        }
        $this->backgroundMinute = $minute;
        // The minute's own caps apply when the lines are added up.
        self::add($this->background, $db, $statement, $ms, $failed, self::HARD_MAX_KEYS);
        if (!$this->shutdown) {
            $this->shutdown = true;
            register_shutdown_function(array($this, 'onShutdown'));
        }
    }

    private function mergeBackground(array $row)
    {
        if (!$this->background) {
            $this->backgroundMinute = (int) (floor(time() / 60) * 60);
        }
        $key = $row[0] . "\0" . $row[1];
        if (!isset($this->background[$key])) {
            $this->background[$key] = $row;
            return;
        }
        $into = &$this->background[$key];
        $into[2] += $row[2];
        $into[3] += $row[3];
        $into[4] += $row[4];
        $into[5] = max($into[5], $row[5]);
        foreach ($row[6] as $i => $n) {
            $into[6][$i] += $n;
        }
    }

    private function saveBackground()
    {
        $map = $this->background;
        $this->background = array();
        if ($map) {
            $this->save($this->backgroundMinute ?: time(), 'JOB', self::BACKGROUND, $map);
        }
    }

    // The end of a script: what ran outside any request is written out, and
    // on the command line sent when due, since no request will come along.
    public function onShutdown()
    {
        try {
            $this->saveBackground();
            if (PHP_SAPI === 'cli') {
                $this->core->within(Core::DEADLINE, function () {
                    $this->flush();
                });
            }
        } catch (\Throwable $e) {
            // never break the site
        }
    }

    private function save($at, $method, $route, array $map)
    {
        if (!$this->core->isOn('performance') || !$this->core->ensureDir()) {
            return;
        }
        $rows = array();
        foreach ($map as $row) {
            $rows[] = array($row[0], $row[1], $row[2], $row[3], round($row[4], 3), round($row[5], 3), $row[6]);
        }
        $this->core->append('queries', array('t' => (int) $at, 'm' => (string) $method, 'r' => (string) $route, 'q' => $rows), self::SPOOL_MAX);
    }

    private static function bucketOf($ms)
    {
        foreach (self::BUCKET_EDGES_MS as $i => $edge) {
            if ($ms <= $edge) {
                return $i;
            }
        }
        return count(self::BUCKET_EDGES_MS);
    }

    // ---- Sending ----------------------------------------------------------------

    private function big()
    {
        $file = $this->core->dir() . '/queries.jsonl';
        clearstatcache(true, $file);
        return is_file($file) && filesize($file) > self::SEND_BYTES;
    }

    public function due()
    {
        return $this->core->waiting('queries') && ($this->core->sendDue('queries', self::FLUSH_EVERY) || $this->big());
    }

    // Adds up the recorded lines and sends them, once a minute.
    public function flush($force = false)
    {
        $this->core->drain('queries', $this->big() ? 0 : self::FLUSH_EVERY, $force, function (array $recorded) {
            $rows = array();
            $keys = array();
            foreach ($recorded as $line) {
                if (!isset($line['t'], $line['m'], $line['r'], $line['q']) || !is_array($line['q'])) {
                    continue;
                }
                $minute = (int) (floor($line['t'] / 60) * 60);
                $method = Performance::method($line['m']);
                $route = (string) $line['r'];
                foreach ($line['q'] as $q) {
                    if (!is_array($q) || count($q) < 7 || !is_array($q[6])) {
                        continue;
                    }
                    $db = self::databaseOf($q[0]);
                    $statement = (string) $q[1];
                    $key = json_encode(array($minute, $method, $route, $db, $statement));
                    $count = isset($keys[$minute]) ? $keys[$minute] : 0;
                    if (!isset($rows[$key]) && $count >= self::MAX_KEYS) {
                        $statement = self::OTHER;
                        $key = json_encode(array($minute, $method, $route, $db, $statement));
                    }
                    if (!isset($rows[$key]) && $count >= self::HARD_MAX_KEYS) {
                        continue;
                    }
                    if (!isset($rows[$key])) {
                        $keys[$minute] = $count + 1;
                        $rows[$key] = array(
                            'minute' => gmdate('Y-m-d\TH:i:s.000\Z', $minute), 'method' => $method, 'route' => $route,
                            'db' => $db, 'statement' => $statement, 'count' => 0, 'errors' => 0, 'sum_ms' => 0.0, 'max_ms' => 0.0,
                            'buckets' => array_fill(0, count(self::BUCKET_EDGES_MS) + 1, 0),
                        );
                    }
                    $rows[$key]['count'] += (int) $q[2];
                    $rows[$key]['errors'] += (int) $q[3];
                    $rows[$key]['sum_ms'] += (float) $q[4];
                    $rows[$key]['max_ms'] = max($rows[$key]['max_ms'], (float) $q[5]);
                    foreach ($rows[$key]['buckets'] as $i => $n) {
                        $rows[$key]['buckets'][$i] = $n + (isset($q[6][$i]) ? (int) $q[6][$i] : 0);
                    }
                }
            }
            foreach ($rows as $key => $row) {
                $rows[$key]['sum_ms'] = round($row['sum_ms'], 1);
                $rows[$key]['max_ms'] = round($row['max_ms'], 1);
            }
            foreach (array_chunk(array_values($rows), self::MAX_ROWS) as $batch) {
                $this->core->post('queries', '/events/server-queries', array(
                    'site_id' => (string) $this->core->opt('site_id'),
                    'server_name' => substr((string) $this->options['server_name'], 0, 100),
                    'runtime' => 'PHP ' . PHP_VERSION,
                    'rows' => $batch,
                ), 'bearer');
            }
        });
    }

    // ---- MongoDB ----------------------------------------------------------------

    // The mongodb extension's global command subscriber, once per process,
    // when the extension is loaded. Its public monitoring API: nothing of
    // the driver is patched.
    public static function watchMongo()
    {
        if (self::$mongo || !function_exists('MongoDB\\Driver\\Monitoring\\addSubscriber')
            || !interface_exists('MongoDB\\Driver\\Monitoring\\CommandSubscriber')) {
            return false;
        }
        self::$mongo = true;
        // Declared only here, so this file loads without the extension.
        \MongoDB\Driver\Monitoring\addSubscriber(new class implements \MongoDB\Driver\Monitoring\CommandSubscriber {
            // The commands started and not yet finished, by request id.
            private $started = array();

            public function commandStarted($event): void
            {
                try {
                    $text = Queries::mongoText($event->getCommandName(), $event->getCommand());
                } catch (\Throwable $e) {
                    return;
                }
                if ($text === '') {
                    return;
                }
                if (count($this->started) >= 1000) {
                    $this->started = array();
                }
                $this->started[(string) $event->getRequestId()] = $text;
            }

            public function commandSucceeded($event): void
            {
                $this->finish($event, false);
            }

            public function commandFailed($event): void
            {
                $this->finish($event, true);
            }

            private function finish($event, $failed)
            {
                $id = (string) $event->getRequestId();
                if (!isset($this->started[$id])) {
                    return;
                }
                $text = $this->started[$id];
                unset($this->started[$id]);
                Queries::report('mongodb', $text, $event->getDurationMicros() / 1000, $failed);
            }
        });
        return true;
    }

    // "<command> <collection> <filter as JSON>", as the protocol has the
    // package build it; '' for connection chatter.
    public static function mongoText($name, $command)
    {
        $name = (string) $name;
        if ($name === '' || in_array($name, self::MONGO_CHATTER, true)) {
            return '';
        }
        $command = is_object($command) ? $command : (object) (array) $command;
        $collection = isset($command->{$name}) && is_string($command->{$name}) ? $command->{$name} : '';
        $filter = null;
        if ($name === 'find' && isset($command->filter)) {
            $filter = $command->filter;
        } elseif ($name === 'aggregate' && isset($command->pipeline)) {
            $filter = $command->pipeline;
        } elseif (in_array($name, array('count', 'distinct', 'findAndModify'), true) && isset($command->query)) {
            $filter = $command->query;
        } elseif ($name === 'delete' || $name === 'update') {
            $field = $name . 's'; // deletes, updates
            $list = isset($command->{$field}) ? $command->{$field} : null;
            $first = is_array($list) && $list ? reset($list) : null;
            if (is_object($first) && isset($first->q)) {
                $filter = $first->q;
            } elseif (is_array($first) && isset($first['q'])) {
                $filter = $first['q'];
            }
        }
        $text = $name . ($collection !== '' ? ' ' . $collection : '');
        if ($filter !== null) {
            // BSON types write themselves as extended JSON ({"$oid": ...}),
            // and every value is "?" once normalized.
            $json = json_encode($filter, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE | JSON_PARTIAL_OUTPUT_ON_ERROR);
            if (is_string($json) && $collection !== '') {
                $text .= ' ' . $json;
            }
        }
        return $text;
    }

    // ---- Normalizing ------------------------------------------------------------
    // expresscollect/Analytics/queryText.js, ported character for character:
    // sdk/protocols/query-cases.json is run against this (test/QueriesTest.php).
    // It scans bytes, not characters: everything the rule looks for is ASCII,
    // and no byte of a multi-byte UTF-8 character is, except JavaScript's
    // whitespace (its \s and trim()), matched here by its UTF-8 bytes. So it
    // gives JavaScript's answer for any valid UTF-8 and never fails on bytes
    // that aren't.

    // JavaScript's whitespace: \t \n \v \f \r, space, and U+00A0, U+1680,
    // U+2000-200A, U+2028, U+2029, U+202F, U+205F, U+3000, U+FEFF.
    const WS = '(?:[\t\n\x0B\f\r ]|\xC2\xA0|\xE1\x9A\x80|\xE2\x80[\x80-\x8A\xA8\xA9\xAF]|\xE2\x81\x9F|\xE3\x80\x80|\xEF\xBB\xBF)';
    const PLACEHOLDER = '(?:\?|\$[0-9]+|:[A-Za-z0-9_]+|@[A-Za-z0-9_]+)';
    // Bytes the scan stops at; any other byte is copied as it is.
    const SPECIAL = "-#/'\"`\$0123456789.\t\n\x0B\f\r \xC2\xE1\xE2\xE3\xEF";

    public static function databaseOf($db)
    {
        $name = strtolower(is_scalar($db) ? (string) $db : '');
        return in_array($name, self::DATABASES, true) ? $name : 'other';
    }

    // A driver's own name for its database (PDO's, Laravel's, Doctrine's)
    // as the protocol names it.
    public static function databaseOfDriver($driver)
    {
        $name = strtolower((string) $driver);
        $map = array(
            'pgsql' => 'postgresql', 'pdo_pgsql' => 'postgresql', 'postgres' => 'postgresql', 'postgresql' => 'postgresql',
            'mysql' => 'mysql', 'pdo_mysql' => 'mysql', 'mysqli' => 'mysql', 'mariadb' => 'mariadb',
            'sqlite' => 'sqlite', 'pdo_sqlite' => 'sqlite', 'sqlite3' => 'sqlite',
            'sqlsrv' => 'mssql', 'pdo_sqlsrv' => 'mssql', 'dblib' => 'mssql', 'mssql' => 'mssql',
            'oci' => 'oracle', 'oci8' => 'oracle', 'pdo_oci' => 'oracle', 'oracle' => 'oracle',
            'mongodb' => 'mongodb',
        );
        return isset($map[$name]) ? $map[$name] : 'other';
    }

    // The statement to store, or '' when nothing is left of it.
    public static function normalize($text, $db)
    {
        if (!is_string($text)) {
            return '';
        }
        if ($text === self::OTHER) {
            return $text;
        }
        $db = self::databaseOf($db);
        return self::cut($db === 'mongodb' ? self::mongoStatement($text) : self::sqlShape($text, $db));
    }

    // normalize(), remembered for the statements a request runs again.
    private static function statement($sql, $db)
    {
        if (!is_string($sql) || strlen($sql) > 4000) {
            return self::normalize($sql, $db);
        }
        $key = $db . "\0" . $sql;
        if (!isset(self::$cache[$key])) {
            if (count(self::$cache) >= 500) {
                self::$cache = array();
            }
            self::$cache[$key] = self::normalize($sql, $db);
        }
        return self::$cache[$key];
    }

    // The byte length of the whitespace character at $i, or 0.
    private static function spaceAt($s, $i)
    {
        $c = $s[$i];
        if ($c === ' ' || $c === "\t" || $c === "\n" || $c === "\r" || $c === "\x0B" || $c === "\f") {
            return 1;
        }
        $o = ord($c);
        if ($o !== 0xC2 && $o !== 0xE1 && $o !== 0xE2 && $o !== 0xE3 && $o !== 0xEF) {
            return 0;
        }
        return preg_match('/\G' . self::WS . '/', $s, $m, 0, $i) ? strlen($m[0]) : 0;
    }

    // [A-Za-z0-9_$@:]: a digit after one is part of a name or placeholder.
    private static function isWord($c)
    {
        return $c !== '' && (ctype_alnum($c) && ord($c) < 128 || $c === '_' || $c === '$' || $c === '@' || $c === ':');
    }

    private static function trimJs($s)
    {
        $start = 0;
        $n = strlen($s);
        while ($start < $n && ($w = self::spaceAt($s, $start)) > 0) {
            $start += $w;
        }
        $end = $n;
        while ($end > $start) {
            if (strpos("\t\n\x0B\f\r ", $s[$end - 1]) !== false) {
                $end--;
                continue;
            }
            if ($end - $start >= 2 && substr($s, $end - 2) === "\xC2\xA0") {
                $end -= 2;
                continue;
            }
            if ($end - $start >= 3 && preg_match('/' . self::WS . '\z/', substr($s, $end - 3, 3))) {
                $end -= 3;
                continue;
            }
            break;
        }
        return substr($s, $start, $end - $start);
    }

    // The end of a quoted run starting at $start (the opening quote): the
    // index after the closing quote, or the text's length. A doubled quote
    // and a backslash both escape.
    private static function quoteEnd($sql, $start, $quote)
    {
        $n = strlen($sql);
        $i = $start + 1;
        while ($i < $n) {
            $i += strcspn($sql, $quote . '\\', $i);
            if ($i >= $n) {
                break;
            }
            if ($sql[$i] === '\\') {
                $i += 2;
            } elseif ($i + 1 < $n && $sql[$i + 1] === $quote) {
                $i += 2;
            } else {
                return $i + 1;
            }
        }
        return $n;
    }

    private static function sqlShape($sql, $db)
    {
        $mysql = $db === 'mysql' || $db === 'mariadb';
        $out = '';
        $n = strlen($sql);
        $i = 0;
        while ($i < $n) {
            $run = strcspn($sql, self::SPECIAL, $i);
            if ($run > 0) {
                $out .= substr($sql, $i, $run);
                $i += $run;
                continue;
            }
            $c = $sql[$i];
            $next = $i + 1 < $n ? $sql[$i + 1] : '';
            $prev = $i > 0 ? $sql[$i - 1] : '';
            if (($c === '-' && $next === '-') || ($c === '#' && $mysql)) {
                $end = strpos($sql, "\n", $i);
                $i = $end === false ? $n : $end;
                self::space($out);
            } elseif ($c === '/' && $next === '*') {
                $end = strpos($sql, '*/', $i + 2);
                $i = $end === false ? $n : $end + 2;
                self::space($out);
            } elseif ($c === "'" || ($c === '"' && $mysql)) {
                // A string's one-letter prefix: E'..' N'..' X'..' B'..'.
                $len = strlen($out);
                if ($len > 0 && strpos('EeNnXxBb', $out[$len - 1]) !== false
                    && ($len === 1 || !(ctype_alnum($out[$len - 2]) && ord($out[$len - 2]) < 128 || $out[$len - 2] === '_'))) {
                    $out = substr($out, 0, -1);
                }
                $i = self::quoteEnd($sql, $i, $c);
                $out .= '?';
            } elseif ($c === '"' || $c === '`') {
                $end = self::quoteEnd($sql, $i, $c);
                $out .= substr($sql, $i, $end - $i);
                $i = $end;
            } elseif ($c === '$' && !self::isWord($prev) && preg_match('/^\$(?:[A-Za-z_][A-Za-z0-9_]*)?\$/', substr($sql, $i, 64), $m)) {
                $tag = $m[0];
                $end = strpos($sql, $tag, $i + strlen($tag));
                $i = $end === false ? $n : $end + strlen($tag);
                $out .= '?';
            } elseif ((ctype_digit($c) || ($c === '.' && $next !== '' && ctype_digit($next))) && !self::isWord($prev)) {
                preg_match('/^(?:0[xX][0-9a-fA-F]+|(?:[0-9]+\.?[0-9]*|\.[0-9]+)(?:[eE][+-]?[0-9]+)?)/', substr($sql, $i, 400), $m);
                $i += strlen($m[0]);
                $out .= '?';
            } elseif (($w = self::spaceAt($sql, $i)) > 0) {
                $i += $w;
                self::space($out);
            } else {
                $out .= $c;
                $i += 1;
            }
        }
        // A list of only placeholders is one (?), and so are rows of them.
        $out = preg_replace('/\(' . self::WS . '*' . self::PLACEHOLDER . '(?:' . self::WS . '*,' . self::WS . '*' . self::PLACEHOLDER . ')*' . self::WS . '*\)/', '(?)', $out);
        $out = preg_replace('/\(\?\)(?:' . self::WS . '*,' . self::WS . '*\(\?\))+/', '(?)', $out);
        return self::trimJs((string) $out);
    }

    private static function space(&$out)
    {
        if ($out !== '' && substr($out, -1) !== ' ') {
            $out .= ' ';
        }
    }

    // Where the run of non-whitespace starting at $i ends.
    private static function wordEnd($s, $i)
    {
        $n = strlen($s);
        while ($i < $n) {
            $i += strcspn($s, "\t\n\x0B\f\r \xC2\xE1\xE2\xE3\xEF", $i);
            if ($i >= $n || self::spaceAt($s, $i) > 0) {
                return $i;
            }
            $i++;
        }
        return $n;
    }

    // "find users {...}": the command, the collection, and the filter's shape.
    // The split is queryText.js's /^(\S+)(?: (\S+))?(?: ([\s\S]*))?$/, worked
    // out by hand.
    private static function mongoStatement($text)
    {
        $text = self::trimJs($text);
        $n = strlen($text);
        if ($n === 0) {
            return '';
        }
        $p = self::wordEnd($text, 0);
        $command = substr($text, 0, $p);
        $collection = '';
        $rest = '';
        if ($p < $n) {
            if ($text[$p] !== ' ') {
                return '';
            }
            $q = self::wordEnd($text, $p + 1);
            if ($q > $p + 1 && ($q === $n || $text[$q] === ' ')) {
                $collection = substr($text, $p + 1, $q - $p - 1);
                $rest = $q < $n ? substr($text, $q + 1) : '';
            } else {
                $rest = substr($text, $p + 1);
            }
        }
        // A "collection" with a brace, bracket or quote in it is the filter's start.
        if ($collection !== '' && strpbrk($collection, '{}[]"\'') !== false) {
            $rest = $rest === '' ? $collection : $collection . ' ' . $rest;
            $collection = '';
        }
        $shape = '';
        if ($rest !== '') {
            // Objects as objects, so {} and [] stay apart and keys keep their order.
            $value = json_decode($rest, false, 100000);
            if (json_last_error() === JSON_ERROR_NONE) {
                $shape = self::mongoShape($value, 0);
            }
        }
        $parts = array($command);
        if ($collection !== '') {
            $parts[] = $collection;
        }
        if ($shape !== '') {
            $parts[] = $shape;
        }
        return implode(' ', $parts);
    }

    // A filter or pipeline's shape, as JSON: keys kept, every value "?", an
    // array whose items all have the same shape kept as one, and anything
    // deeper than six levels "?". Keys come out in JavaScript's order
    // (integer keys first, ascending), and "__proto__" not at all, as
    // queryText.js's object gives them.
    private static function mongoShape($value, $depth)
    {
        if ($depth >= 6 || !(is_array($value) || $value instanceof \stdClass)) {
            return '"?"';
        }
        if (is_array($value)) {
            $items = array();
            foreach ($value as $item) {
                $items[] = self::mongoShape($item, $depth + 1);
            }
            return '[' . (count(array_unique($items)) === 1 ? $items[0] : implode(',', $items)) . ']';
        }
        $numbered = array();
        $named = array();
        foreach ($value as $key => $item) {
            $key = (string) $key;
            if ($key === '__proto__') {
                continue;
            }
            if (preg_match('/^(?:0|[1-9][0-9]{0,9})\z/', $key) && (float) $key <= 4294967294) {
                $numbered[$key] = $item;
            } else {
                $named[$key] = $item;
            }
        }
        uksort($numbered, function ($a, $b) {
            return (float) $a <=> (float) $b;
        });
        $parts = array();
        foreach (array($numbered, $named) as $group) {
            foreach ($group as $key => $item) {
                $parts[] = json_encode((string) $key, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_LINE_TERMINATORS)
                    . ':' . self::mongoShape($item, $depth + 1);
            }
        }
        return '{' . implode(',', $parts) . '}';
    }

    // At most MAX_STATEMENT code points, trimmed again when cut.
    private static function cut($text)
    {
        if (strlen($text) <= self::MAX_STATEMENT) {
            return $text;
        }
        if (function_exists('mb_strlen')) {
            if (mb_strlen($text, 'UTF-8') <= self::MAX_STATEMENT) {
                return $text;
            }
            return self::trimJs(mb_substr($text, 0, self::MAX_STATEMENT, 'UTF-8'));
        }
        // Without mbstring: a code point is a byte that doesn't continue one.
        if (preg_match_all('/[^\x80-\xBF]/', $text) <= self::MAX_STATEMENT) {
            return $text;
        }
        preg_match('/^(?:[^\x80-\xBF][\x80-\xBF]*){' . self::MAX_STATEMENT . '}/', $text, $m);
        return self::trimJs($m[0]);
    }
}
