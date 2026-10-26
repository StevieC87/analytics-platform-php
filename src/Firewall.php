<?php
// The firewall module of the PHP package, run from the analytics dashboard
// (Security → Firewall); the protocol is sdk/protocols/firewall.md. Used
// through Platform (all modules) or on its own, and by the WordPress plugin,
// which ships a copy of src/ (sdk/wordpress-plugin/build.sh).
//
// PHP keeps nothing between requests, so everything lives in the storage
// directory:
// - rules.php: the last rules, compiled and written as PHP so OPcache keeps
//   them in memory. Each request includes it; nothing waits on the network.
// - Rules are fetched after the response is sent (shutdown), when older than
//   the rules' sync interval, by one request at a time (sync.lock).
// - events.jsonl: what was blocked, appended per request and sent in batches.
// Rate limits need a counter shared between requests: APCu, or the
// `counter` option; without either there is no rate limit.
// Fails open: no rules, unreadable rules or an unreachable collector let
// every request through.

namespace AnalyticsPlatform;

class Firewall
{
    const PROTOCOL = 1;
    const MIN_SYNC = 30;
    const RETRY = 60;
    const FLUSH_EVERY = 5;
    const BATCH = 200;
    const SPOOL_MAX = 2000000; // bytes of events waiting; more are dropped
    const RULES = array('allow', 'deny', 'banned', 'lists', 'shared', 'goodbots');
    // Cloudflare's published ranges (cloudflare.com/ips), the same list as
    // sdk/protocols/cloudflare-ranges.json: CF-Connecting-IP is believed only
    // from these, since anyone who reaches the origin directly can send it.
    const CLOUDFLARE = array(
        '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22', '141.101.64.0/18',
        '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22', '198.41.128.0/17',
        '162.158.0.0/15', '104.16.0.0/13', '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
        '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32', '2405:8100::/32',
        '2a06:98c0::/29', '2c0f:f248::/32',
    );
    private static $cloudflare = null;

    private $options;
    private $core;
    private $dir;
    private $rules = null;
    private $loaded = false;
    private $reported = false;

    // Options: site_id, secret, endpoint (required); storage (a writable
    // directory; default the system temp directory); trust_proxy (0: the
    // connection's address; a number of proxies in X-Forwarded-For;
    // 'cloudflare': CF-Connecting-IP, believed only from Cloudflare's own
    // addresses); mode ('monitor' or 'block', overrides the dashboard);
    // counter (callable($key, $ttl): int, the hit count after
    // adding one); platform (for the dashboard, default 'php'); on_block
    // (callable($decision), send your own response). $core: shared with the
    // other modules (Platform passes it).
    public function __construct(array $options, ?Core $core = null)
    {
        $this->options = $options + array(
            'trust_proxy' => 0,
            'mode' => null,
            'counter' => null,
            'on_block' => null,
        );
        $this->core = $core ?: new Core($options);
        $this->dir = $this->core->dir();
        if (!$this->counterAvailable()) {
            $this->core->features = ' (no-rate)';
        }
    }

    private function opt($key)
    {
        return $this->core->opt($key);
    }

    public function configured()
    {
        return $this->core->configured();
    }

    // Checks the current request and ends it when blocked. Rules and events
    // are synced after the response ($afterResponse false: the caller runs
    // afterResponse() itself, as Platform does).
    public function protect($afterResponse = true)
    {
        if (!$this->configured() || PHP_SAPI === 'cli') {
            return;
        }
        if ($afterResponse) {
            register_shutdown_function(array($this, 'afterResponse'));
        }
        try {
            $path = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '';
            $decision = $this->check(
                $this->clientIp(),
                isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : '',
                $path,
                isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : ''
            );
        } catch (\Throwable $e) {
            return;
        }
        if ($decision['action'] !== 'block') {
            return;
        }
        if (is_callable($this->options['on_block'])) {
            call_user_func($this->options['on_block'], $decision);
            exit;
        }
        if (!headers_sent()) {
            http_response_code($decision['status']);
            header('Content-Type: text/plain; charset=utf-8');
            header('Cache-Control: no-store');
            if ($decision['status'] === 429) {
                header('Retry-After: ' . $this->rules['rate']['window']);
            }
        }
        echo $decision['status'] === 429 ? 'Too Many Requests' : 'Forbidden';
        exit;
    }

    // The visitor's address, per trust_proxy.
    public function clientIp()
    {
        $direct = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '';
        $trust = $this->options['trust_proxy'];
        if ($trust === 'cloudflare') {
            if (empty($_SERVER['HTTP_CF_CONNECTING_IP']) || !self::fromCloudflare($direct)) {
                return $direct;
            }
            return trim($_SERVER['HTTP_CF_CONNECTING_IP']);
        }
        $hops = (int) $trust;
        if ($hops > 0 && !empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $chain = array_values(array_filter(array_map('trim', explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']))));
            if ($chain) {
                return $chain[max(0, count($chain) - $hops)];
            }
        }
        return $direct;
    }

    // Whether the connection came from Cloudflare.
    public static function fromCloudflare($ip)
    {
        $key = self::ipKey($ip);
        if ($key === null) {
            return false;
        }
        if (self::$cloudflare === null) {
            self::$cloudflare = self::compileList(self::CLOUDFLARE);
        }
        return self::has(self::$cloudflare, $key);
    }

    // array('action' => 'allow' | 'block' | 'monitor', 'rule' => ..., 'status' => ...).
    public function check($ip, $method = '', $path = '', $userAgent = '')
    {
        $allow = array('action' => 'allow', 'rule' => '', 'status' => 200);
        $rules = $this->rules();
        if (!$rules || empty($rules['enabled'])) {
            return $allow;
        }
        $key = self::ipKey($ip);
        if ($key === null || self::has($rules['allow'], $key)) {
            return $allow;
        }
        $rule = '';
        if (self::has($rules['deny'], $key)) {
            $rule = 'deny';
        } elseif ((isset($rules['banned']) && self::has($rules['banned'], $key)) || $this->bannedHere($key)) {
            $rule = 'ban';
        } elseif (self::has($rules['lists'], $key)) {
            $rule = 'list';
        } elseif (self::has($rules['shared'], $key)) {
            $rule = 'shared';
        } elseif (!empty($rules['probes']) && self::isProbe($rules['probes'], $path)) {
            $rule = 'probe';
        } elseif (($matched = RequestRules::matchRequest(isset($rules['requests']) ? $rules['requests'] : array(), $method, $path, $userAgent))) {
            $rule = 'request:' . $matched['id'];
        } elseif ($rules['rate'] && !self::has(isset($rules['goodbots']) ? $rules['goodbots'] : array(), $key) && $this->overRate($key, $rules['rate'])) {
            $rule = 'rate';
        }
        if ($rule === '') {
            return $allow;
        }
        $mode = in_array($this->options['mode'], array('monitor', 'block'), true) ? $this->options['mode'] : $rules['mode'];
        $action = $mode === 'block' ? 'block' : 'monitor';
        // A request rule the dashboard only watches passes even in block mode;
        // one that blocks also bans the address here, as a flood does.
        if (isset($matched) && $matched) {
            $action = $action === 'block' && $matched['action'] === 'block' ? 'block' : 'monitor';
            if ($action === 'block' && $matched['ban']) {
                $this->banHere($key, $matched['ban']);
            }
        }
        // Asking for a secret file: banned here (with APCu); the report bans it on the site's other servers.
        if ($rule === 'probe' && $action === 'block') {
            $this->banHere($key, $rules['probes']['ban']);
        }
        // Over the rate limit: the same, banned here only in block mode.
        if ($rule === 'rate' && $action === 'block') {
            $this->banHere($key, isset($rules['ban']) ? $rules['ban'] : 0);
        }
        $this->report(array(
            'at' => gmdate('Y-m-d\TH:i:s\Z'),
            'ip' => (string) $ip,
            'rule' => $rule,
            'action' => $action,
            'method' => substr((string) $method, 0, 10),
            'path' => substr(explode('?', (string) $path, 2)[0], 0, 300),
            'user_agent' => substr((string) $userAgent, 0, 300),
        ));
        return array('action' => $action, 'rule' => $rule, 'status' => $rule === 'rate' ? 429 : 403);
    }

    // What the rules say now, for a status page: null before the first sync.
    public function status()
    {
        $rules = $this->rules();
        if (!$rules) {
            return null;
        }
        $counts = array();
        foreach (self::RULES as $list) {
            $counts[$list] = count($rules[$list]);
        }
        return array(
            'enabled' => $rules['enabled'],
            'mode' => $rules['mode'],
            'fetched' => $rules['fetched'],
            'rate' => $rules['rate'],
            'rate_available' => $this->counterAvailable(),
            'ranges' => $counts,
        );
    }

    // ---- Addresses --------------------------------------------------------
    // Every address as 32 hex digits of its 16-byte IPv6 form (IPv4 as
    // ::ffff:a.b.c.d), so one sorted list and string comparison cover both.

    public static function ipKey($ip)
    {
        $bin = @inet_pton(trim((string) $ip));
        if ($bin === false) {
            return null;
        }
        if (strlen($bin) === 4) {
            $bin = str_repeat("\0", 10) . "\xff\xff" . $bin;
        }
        return bin2hex($bin);
    }

    // "1.2.3.0/24" -> array(start, end) as ipKey()s; null when invalid.
    public static function range($entry)
    {
        $parts = explode('/', trim((string) $entry));
        if (count($parts) > 2) {
            return null;
        }
        $bin = @inet_pton($parts[0]);
        if ($bin === false) {
            return null;
        }
        $v4 = strlen($bin) === 4;
        if ($v4) {
            $bin = str_repeat("\0", 10) . "\xff\xff" . $bin;
        }
        $prefix = 128;
        if (isset($parts[1])) {
            if (!ctype_digit($parts[1]) || (int) $parts[1] > ($v4 ? 32 : 128)) {
                return null;
            }
            $prefix = (int) $parts[1] + ($v4 ? 96 : 0);
        }
        $start = '';
        $end = '';
        for ($i = 0; $i < 16; $i++) {
            $bits = max(0, min(8, $prefix - 8 * $i));
            $mask = $bits === 0 ? 0 : (0xff << (8 - $bits)) & 0xff;
            $byte = ord($bin[$i]) & $mask;
            $start .= chr($byte);
            $end .= chr($byte | (~$mask & 0xff));
        }
        return array(bin2hex($start), bin2hex($end));
    }

    // Entries -> sorted, merged ranges.
    public static function compileList($entries)
    {
        $ranges = array();
        foreach (is_array($entries) ? $entries : array() as $entry) {
            if (is_string($entry) && ($range = self::range($entry))) {
                $ranges[] = $range;
            }
        }
        usort($ranges, function ($a, $b) {
            return strcmp($a[0], $b[0]);
        });
        $merged = array();
        foreach ($ranges as $range) {
            $last = count($merged) - 1;
            if ($last >= 0 && strcmp($range[0], $merged[$last][1]) <= 0) {
                if (strcmp($range[1], $merged[$last][1]) > 0) {
                    $merged[$last][1] = $range[1];
                }
            } else {
                $merged[] = $range;
            }
        }
        return $merged;
    }

    // Whether an ipKey() is in a compileList() (used by maintenance mode's allowed addresses).
    public static function inList(array $ranges, $key)
    {
        return self::has($ranges, $key);
    }

    private static function has(array $ranges, $key)
    {
        $lo = 0;
        $hi = count($ranges) - 1;
        while ($lo <= $hi) {
            $mid = ($lo + $hi) >> 1;
            if (strcmp($ranges[$mid][0], $key) > 0) {
                $hi = $mid - 1;
            } elseif (strcmp($ranges[$mid][1], $key) < 0) {
                $lo = $mid + 1;
            } else {
                return true;
            }
        }
        return false;
    }

    // ---- Probes -----------------------------------------------------------
    // Addresses of files no visitor asks for (.env, .git/, backups): only
    // scanners looking for secrets do.

    public static function compileProbes($probes)
    {
        if (!is_array($probes)) {
            return null;
        }
        $exact = array();
        foreach (isset($probes['exact']) && is_array($probes['exact']) ? $probes['exact'] : array() as $path) {
            if (is_string($path) && $path !== '') {
                $exact[strtolower($path)] = true;
            }
        }
        $prefix = array();
        foreach (isset($probes['prefix']) && is_array($probes['prefix']) ? $probes['prefix'] : array() as $path) {
            if (is_string($path) && $path !== '') {
                $prefix[] = strtolower($path);
            }
        }
        if (!$exact && !$prefix) {
            return null;
        }
        return array('exact' => $exact, 'prefix' => $prefix, 'ban' => isset($probes['ban']) ? max(0, (int) $probes['ban']) : 0);
    }

    // The path without its query string, lower-cased, with "//" as "/".
    public static function isProbe(array $probes, $path)
    {
        $path = strtolower(preg_replace('#/{2,}#', '/', explode('?', (string) $path, 2)[0]));
        if (isset($probes['exact'][$path])) {
            return true;
        }
        foreach ($probes['prefix'] as $prefix) {
            if (strpos($path, $prefix) === 0) {
                return true;
            }
        }
        return false;
    }

    // ---- Rules ------------------------------------------------------------

    private function rules()
    {
        if (!$this->loaded) {
            $this->loaded = true;
            $rules = $this->core->readPhp('rules.php');
            $this->rules = is_array($rules) && isset($rules['v']) && $rules['v'] === self::PROTOCOL ? $rules : null;
        }
        return $this->rules;
    }

    private function compile(array $data, $etag)
    {
        $rate = null;
        if (!empty($data['rate']['limit']) && (int) $data['rate']['limit'] > 0) {
            $rate = array('limit' => (int) $data['rate']['limit'], 'window' => max(1, (int) (isset($data['rate']['window']) ? $data['rate']['window'] : 60)));
        }
        $rules = array(
            'v' => self::PROTOCOL,
            'etag' => (string) $etag,
            'fetched' => time(),
            'enabled' => !empty($data['enabled']),
            'mode' => isset($data['mode']) && $data['mode'] === 'block' ? 'block' : 'monitor',
            'sync' => max(self::MIN_SYNC, (int) (isset($data['sync']) ? $data['sync'] : self::RETRY)),
            'rate' => $rate,
            // Bot protection: how long to ban a flood, and the failed-login limit.
            'ban' => isset($data['ban']['seconds']) ? max(0, (int) $data['ban']['seconds']) : 0,
            'login' => !empty($data['login']['limit']) ? array(
                'limit' => (int) $data['login']['limit'],
                'window' => (int) (isset($data['login']['window']) ? $data['login']['window'] : 3600),
                'ban' => (int) (isset($data['login']['ban']) ? $data['login']['ban'] : 3600),
            ) : null,
            'probes' => self::compileProbes(isset($data['probes']) ? $data['probes'] : null),
            // Virtual patching: rules that match the request, not the address.
            'requests' => RequestRules::compile(isset($data['requests']) ? $data['requests'] : null),
        );
        foreach (self::RULES as $list) {
            $rules[$list] = self::compileList(isset($data[$list]) ? $data[$list] : array());
        }
        return $rules;
    }

    private function writeRules(array $rules)
    {
        if ($this->core->writePhp('rules.php', $rules)) {
            $this->rules = $rules;
        }
    }

    // Fetches rules when due; one request at a time, at most once per
    // MIN_SYNC seconds even when fetches fail.
    public function sync($force = false)
    {
        if (!$this->configured() || !$this->core->ensureDir()) {
            return false;
        }
        $rules = $this->rules();
        $due = $rules ? $rules['fetched'] + $rules['sync'] : 0;
        if (!$force && time() < $due) {
            return true;
        }
        $lockFile = $this->dir . '/sync.lock';
        clearstatcache(true, $lockFile);
        if (!$force && is_file($lockFile) && filemtime($lockFile) > time() - self::MIN_SYNC) {
            return true;
        }
        $lock = @fopen($lockFile, 'c');
        if (!$lock || !flock($lock, LOCK_EX | LOCK_NB)) {
            return true;
        }
        @touch($lockFile);
        $ok = false;
        $headers = array();
        if ($rules && $rules['etag'] !== '' && !$force) {
            $headers[] = 'If-None-Match: ' . $rules['etag'];
        }
        $res = $this->core->http('GET', '/events/firewall/rules?site_id=' . rawurlencode($this->opt('site_id')), null, $headers);
        if ($res['status'] === 200) {
            $data = json_decode($res['body'], true);
            if (is_array($data) && isset($data['v']) && $data['v'] === self::PROTOCOL) {
                $this->writeRules($this->compile($data, isset($res['headers']['etag']) ? $res['headers']['etag'] : ''));
                $ok = true;
            }
        } elseif ($res['status'] === 304 && $rules) {
            $rules['fetched'] = time();
            $this->writeRules($rules);
            $ok = true;
        }
        flock($lock, LOCK_UN);
        fclose($lock);
        return $ok;
    }

    // ---- Rate limit -------------------------------------------------------

    private function counterAvailable()
    {
        return is_callable($this->options['counter']) || (function_exists('apcu_enabled') && apcu_enabled());
    }

    // ---- Bot protection ----------------------------------------------------
    // Bans and failed-login counts on this server need memory shared between
    // requests (APCu). Without it, the collector bans the address and every
    // server gets it with the next rules (within a minute or so).

    private function apcu()
    {
        return function_exists('apcu_enabled') && apcu_enabled();
    }

    private function bannedHere($key)
    {
        return $this->apcu() && apcu_fetch('afw:ban:' . $this->opt('site_id') . ':' . $key) !== false;
    }

    private function banHere($key, $seconds)
    {
        if ($seconds > 0 && $this->apcu()) {
            apcu_store('afw:ban:' . $this->opt('site_id') . ':' . $key, 1, (int) $seconds);
        }
    }

    // A failed login on the site (default: the current visitor's address).
    // Counted here (past the site's limit the address is banned straight
    // away, with APCu) and reported, so it counts on the Security page and
    // gets banned on the site's other servers too.
    public function loginFailed($ip = null)
    {
        try {
            $ip = $ip === null ? $this->clientIp() : (string) $ip;
            $key = self::ipKey($ip);
            $rules = $this->rules();
            if ($key === null || ($rules && self::has($rules['allow'], $key))) {
                return;
            }
            $login = $rules && !empty($rules['login']) ? $rules['login'] : null;
            if ($login && $this->apcu()) {
                $name = 'afw:login:' . $this->opt('site_id') . ':' . $key;
                apcu_add($name, 0, max(60, $login['window']));
                if ((int) apcu_inc($name) >= $login['limit']) {
                    apcu_delete($name);
                    $this->banHere($key, $login['ban']);
                }
            }
            $this->report(array(
                'at' => gmdate('Y-m-d\TH:i:s\Z'), 'ip' => $ip, 'rule' => 'login', 'action' => 'monitor',
                'method' => '', 'path' => '', 'user_agent' => '',
            ));
        } catch (\Throwable $e) {
            // never break the site
        }
    }

    private function overRate($key, array $rate)
    {
        $window = (int) floor(time() / $rate['window']);
        $name = 'afw:' . $this->opt('site_id') . ':' . $key . ':' . $window;
        $ttl = $rate['window'] * 2;
        if (is_callable($this->options['counter'])) {
            $hits = (int) call_user_func($this->options['counter'], $name, $ttl);
        } elseif (function_exists('apcu_enabled') && apcu_enabled()) {
            apcu_add($name, 0, $ttl);
            $hits = (int) apcu_inc($name);
        } else {
            return false;
        }
        return $hits > $rate['limit'];
    }

    // ---- Events -----------------------------------------------------------

    private function report(array $event)
    {
        if ($this->core->ensureDir() && $this->core->append('events', $event, self::SPOOL_MAX)) {
            $this->reported = true;
        }
    }

    // Sends waiting events, grouped like the Node client does, at most every
    // FLUSH_EVERY seconds.
    public function flush($force = false)
    {
        $this->core->drain('events', self::FLUSH_EVERY, $force, function (array $events) {
            $groups = array();
            foreach ($events as $event) {
                if (empty($event['ip'])) {
                    continue;
                }
                $key = json_encode(array($event['ip'], $event['rule'], $event['action'], $event['method'], $event['path']));
                if (isset($groups[$key])) {
                    $groups[$key]['hits']++;
                } else {
                    $groups[$key] = $event + array('hits' => 1);
                }
            }
            foreach (array_chunk(array_values($groups), self::BATCH) as $batch) {
                $this->core->post('events', '/events/firewall/events', array('site_id' => (string) $this->opt('site_id'), 'events' => $batch), 'bearer');
            }
        });
    }

    // Runs at shutdown: finishes the response first where PHP-FPM allows,
    // so the visitor never waits on the sync.
    public function afterResponse()
    {
        try {
            $rules = $this->rules();
            $dueSync = !$rules || time() >= $rules['fetched'] + $rules['sync'];
            $dueFlush = $this->reported || $this->core->waiting('events');
            if (!$dueSync && !$dueFlush) {
                return;
            }
            if (function_exists('fastcgi_finish_request')) {
                @fastcgi_finish_request();
            } elseif (function_exists('litespeed_finish_request')) {
                @litespeed_finish_request();
            }
            if ($dueSync) {
                $this->sync();
            }
            if ($dueFlush) {
                $this->flush();
            }
        } catch (\Throwable $e) {
            // never break the site
        }
    }
}
