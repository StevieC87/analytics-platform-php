<?php
// Performance & API monitoring module: times every request (from PHP
// starting it to the end of the script) and sends one row per minute,
// method, route and status code (how many, total and slowest time, and a
// count per time bucket) to POST /events/server-requests. Nothing about
// visitors is sent.
//
// PHP keeps nothing between requests, so each request appends one line to
// requests.jsonl in the storage directory, and once a minute one request adds
// them up and sends them (after its response). The route is what
// setRoute() was given (Laravel, WordPress set it), else the path with
// numbers and IDs as ":id"; unmatched 404s are one route.

namespace AnalyticsPlatform;

class Performance
{
    // Keep in step with the collector (expresscollect/Analytics/serverRequests.js).
    const BUCKET_EDGES_MS = array(5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000);
    const FLUSH_EVERY = 60;
    const MAX_KEYS = 300;
    const MAX_ROWS = 500;
    const SPOOL_MAX = 5000000; // bytes waiting; more requests aren't recorded
    const NOT_FOUND = '/(not found)';

    private $core;
    private $options;
    private $route = '';

    // Options: server_name (default the host name).
    public function __construct(Core $core, array $options = array())
    {
        $this->core = $core;
        $this->options = $options + array('server_name' => function_exists('gethostname') ? gethostname() : '');
    }

    // The request's route pattern, e.g. "/orders/{id}".
    public function setRoute($route)
    {
        $this->route = substr((string) $route, 0, 200);
    }

    public static function normalizeRoute($path)
    {
        $path = explode('?', (string) $path, 2)[0];
        $path = explode('#', $path, 2)[0];
        $parts = array();
        foreach (explode('/', $path === '' ? '/' : $path) as $segment) {
            $isId = preg_match('/^\d+$/', $segment)
                || preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i', $segment)
                || preg_match('/^[0-9a-f]{16,}$/i', $segment)
                || (strlen($segment) >= 20 && preg_match('/\d/', $segment));
            $parts[] = $isId ? ':id' : $segment;
        }
        $route = implode('/', $parts);
        return substr($route[0] === '/' ? $route : '/' . $route, 0, 200);
    }

    // Records the current request (Platform calls it at shutdown).
    public function recordRequest()
    {
        if (!$this->core->isOn('performance') || !$this->core->ensureDir()) {
            return;
        }
        $started = isset($_SERVER['REQUEST_TIME_FLOAT']) ? (float) $_SERVER['REQUEST_TIME_FLOAT'] : microtime(true);
        $status = (int) http_response_code();
        $status = $status ?: 200;
        $route = $this->route !== '' ? $this->route
            : ($status === 404 ? self::NOT_FOUND : self::normalizeRoute(isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '/'));
        $file = $this->core->dir() . '/requests.jsonl';
        clearstatcache(true, $file);
        if (is_file($file) && filesize($file) > self::SPOOL_MAX) {
            return;
        }
        $line = json_encode(array(
            't' => time(),
            'm' => substr(strtoupper(isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : 'GET'), 0, 10),
            'r' => $route,
            's' => $status,
            'd' => round((microtime(true) - $started) * 1000, 1),
        ));
        @file_put_contents($file, $line . "\n", FILE_APPEND | LOCK_EX);
        $this->route = '';
    }

    public function due()
    {
        $mark = $this->core->dir() . '/requests.lock';
        clearstatcache(true, $mark);
        return is_file($this->core->dir() . '/requests.jsonl') && (!is_file($mark) || filemtime($mark) <= time() - self::FLUSH_EVERY);
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

    // Adds up the recorded requests and sends them, once a minute.
    public function flush($force = false)
    {
        if (!$force && !$this->due()) {
            return;
        }
        $file = $this->core->dir() . '/requests.jsonl';
        $lock = @fopen($this->core->dir() . '/requests.lock', 'c');
        if (!$lock || !flock($lock, LOCK_EX | LOCK_NB)) {
            return;
        }
        @touch($this->core->dir() . '/requests.lock');
        $sending = $file . '.' . getmypid() . '.sending';
        if (@rename($file, $sending)) {
            $rows = array();
            foreach (file($sending, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: array() as $line) {
                $r = json_decode($line, true);
                if (!is_array($r) || !isset($r['t'], $r['m'], $r['r'], $r['s'], $r['d'])) {
                    continue;
                }
                $minute = (int) (floor($r['t'] / 60) * 60);
                $key = $minute . '|' . $r['m'] . '|' . $r['r'] . '|' . $r['s'];
                if (!isset($rows[$key]) && count($rows) >= self::MAX_KEYS) {
                    $key = $minute . '|' . $r['m'] . '|(other)|' . $r['s'];
                }
                if (!isset($rows[$key])) {
                    $parts = explode('|', $key, 4);
                    $rows[$key] = array(
                        'minute' => gmdate('Y-m-d\TH:i:s\Z', $minute), 'method' => $r['m'], 'route' => $parts[2], 'status' => (int) $r['s'],
                        'count' => 0, 'sum_ms' => 0.0, 'max_ms' => 0.0, 'buckets' => array_fill(0, count(self::BUCKET_EDGES_MS) + 1, 0),
                    );
                }
                $ms = (float) $r['d'];
                $rows[$key]['count']++;
                $rows[$key]['sum_ms'] += $ms;
                $rows[$key]['max_ms'] = max($rows[$key]['max_ms'], $ms);
                $rows[$key]['buckets'][self::bucketOf($ms)]++;
            }
            @unlink($sending);
            foreach (array_chunk(array_values($rows), self::MAX_ROWS) as $batch) {
                $this->core->http('POST', '/events/server-requests', array(
                    'server_name' => substr((string) $this->options['server_name'], 0, 100),
                    'runtime' => 'PHP ' . PHP_VERSION,
                    'rows' => $batch,
                ), array(), 'body');
            }
        }
        flock($lock, LOCK_UN);
        fclose($lock);
    }
}
