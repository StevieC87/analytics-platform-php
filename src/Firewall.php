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
// `counter` option; without either there is no rate limit. The browser check
// (Challenge) needs nothing stored: its pass is signed with the site secret.
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
    // IPv4's place in ipKey()'s space: ::ffff:0.0.0.0 to ::ffff:255.255.255.255.
    const MAPPED_START = '00000000000000000000ffff00000000';
    const MAPPED_END = '00000000000000000000ffffffffffff';
    // Files a page load asks for by the dozen: not counted against `rate`
    // (the agent's nginx limit leaves the same extensions out). An address
    // already over the limit is still turned away, and one that answered an
    // error (a flood of made-up /x.css that reaches PHP) is counted after
    // the response, as the agent counts a static 404.
    const STATIC_FILES = '/\\.(?:css|js|mjs|map|png|jpe?g|gif|webp|avif|svg|ico|bmp|woff2?|ttf|otf|eot|mp4|webm|ogg|mp3|wav|pdf|wasm)\\z/i';

    private $options;
    private $core;
    private $dir;
    private $rules = null;
    private $loaded = false;
    private $reported = false;
    // The rate counter a static file would have added to: array(name, ttl).
    private $staticHit = null;

    // Options: site_id, secret, endpoint (required); storage (a writable
    // directory; default the system temp directory); trust_proxy (0: the
    // connection's address; a number of proxies in X-Forwarded-For;
    // 'cloudflare': CF-Connecting-IP, believed only from Cloudflare's own
    // addresses); mode ('monitor' or 'block', overrides the dashboard);
    // counter (callable($key, $ttl): int, the hit count after
    // adding one); platform (for the dashboard, default 'php'); on_block
    // (callable($decision), send your own response; not for the browser
    // check, whose page has to be ours to set the pass). $core: shared with
    // the other modules (Platform passes it).
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

    // The trust_proxy option, as given.
    public function trustProxy()
    {
        return $this->options['trust_proxy'];
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
            $ip = $this->clientIp();
            $method = isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : '';
            $decision = $this->check(
                $ip,
                $method,
                $path,
                isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '',
                isset($_SERVER['HTTP_ACCEPT']) ? $_SERVER['HTTP_ACCEPT'] : '',
                // Every pass the browser sent, from the raw header: $_COOKIE keeps only the first.
                Challenge::cookieValues(isset($_SERVER['HTTP_COOKIE']) ? $_SERVER['HTTP_COOKIE'] : '')
            );
            $page = $decision['rule'] === 'challenge' ? $this->challengePage($ip, $method) : null;
        } catch (\Throwable $e) {
            return;
        }
        if ($decision['action'] !== 'block') {
            return;
        }
        if ($page !== null) {
            if (!headers_sent()) {
                http_response_code($page['status']);
                // Replaces any Content-Security-Policy sent before (the
                // dashboard's security headers): the site's own must not
                // block the page's script.
                foreach ($page['headers'] as $name => $value) {
                    header($name . ': ' . $value);
                }
            }
            echo $page['body'];
            exit;
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
        return self::clientIpFrom($_SERVER, $this->options['trust_proxy']);
    }

    // The visitor's address from $server ($_SERVER's keys), per $trust: 0
    // the connection's address; a number of proxies in X-Forwarded-For;
    // 'cloudflare' CF-Connecting-IP, believed only from Cloudflare's own
    // addresses. A hop that isn't an address (a name, "unknown", what a
    // client wrote) gives the connection's address instead, so the request
    // is still checked; a port on a hop ("203.0.113.5:54321",
    // "[2001:db8::1]:443", as Azure's load balancers send) is dropped. Shared
    // with the WordPress plugin's px.php.
    //
    // Count only the proxies that append to X-Forwarded-For. A web server
    // that already put the visitor in REMOTE_ADDR (Apache's mod_remoteip,
    // nginx's real_ip in front of PHP-FPM, LiteSpeed's "use client IP in
    // header") wants 0: mod_remoteip also takes the entries it used out of
    // the header, so counting them again would read one the visitor wrote.
    public static function clientIpFrom(array $server, $trust)
    {
        $direct = isset($server['REMOTE_ADDR']) ? self::hop($server['REMOTE_ADDR']) : '';
        if ($trust === 'cloudflare') {
            $given = isset($server['HTTP_CF_CONNECTING_IP']) ? self::hop($server['HTTP_CF_CONNECTING_IP']) : '';
            return $given !== '' && self::ipKey($given) !== null && self::fromCloudflare($direct) ? $given : $direct;
        }
        $hops = (int) $trust;
        if ($hops > 0 && !empty($server['HTTP_X_FORWARDED_FOR'])) {
            $chain = array_values(array_filter(array_map('trim', explode(',', (string) $server['HTTP_X_FORWARDED_FOR'])), 'strlen'));
            if ($chain) {
                $chosen = self::hop($chain[max(0, count($chain) - $hops)]);
                return self::ipKey($chosen) !== null ? $chosen : $direct;
            }
        }
        return $direct;
    }

    // One hop as an address: "[v6]:port", "[v6]" and "v4:port" lose the
    // brackets and the port; anything else is returned trimmed, as it was.
    public static function hop($text)
    {
        $text = trim((string) $text);
        if ($text !== '' && $text[0] === '[') {
            $close = strpos($text, ']');
            return $close === false ? $text : substr($text, 1, $close - 1);
        }
        if (preg_match('/^(\d{1,3}(?:\.\d{1,3}){3}):\d{1,5}\z/', $text, $m)) {
            return $m[1];
        }
        return $text;
    }

    // Who the rate limit, the failed-login count and the bans here are
    // about: an IPv4 address (::ffff:a.b.c.d as a.b.c.d), or an IPv6
    // address's /64 as its network ("2001:db8:1:2::/64", compressed and
    // lower-case), which one machine usually holds whole, as the browser
    // check binds its pass. Every package builds the shared counter's key
    // the same way (firewall.md), so a site mixing languages on one Redis
    // counts a visitor once. Null when it isn't an address.
    public static function who($ip)
    {
        $bin = @inet_pton(self::hop($ip));
        if ($bin === false) {
            return null;
        }
        if (strlen($bin) === 16 && substr($bin, 0, 12) === str_repeat("\0", 10) . "\xff\xff") {
            $bin = substr($bin, 12);
        }
        if (strlen($bin) === 4) {
            return inet_ntop($bin);
        }
        return inet_ntop(substr($bin, 0, 8) . str_repeat("\0", 8)) . '/64';
    }

    // Whether a request target asks for a static file (by extension).
    public static function isStatic($path)
    {
        $path = preg_split('/[?#]/', (string) $path, 2)[0];
        return (bool) preg_match(self::STATIC_FILES, $path);
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
    // $accept (the Accept header) and $pass (the __sg_pass cookie, or a list
    // of up to four from Challenge::cookieValues()) are for
    // the browser check: rule 'challenge', status 503, answered with
    // challengePage(). Left out, no request is checked.
    public function check($ip, $method = '', $path = '', $userAgent = '', $accept = '', $pass = '')
    {
        $allow = array('action' => 'allow', 'rule' => '', 'status' => 200);
        // A worker serving many requests (Octane): nothing of the last one's.
        $this->staticHit = null;
        $rules = $this->rules();
        if (!$rules || empty($rules['enabled'])) {
            return $allow;
        }
        $key = self::ipKey($ip);
        if ($key === null || self::has($rules['allow'], $key)) {
            return $allow;
        }
        $who = self::who($ip);
        $rule = $this->addressRule($rules, $key, $who);
        if ($rule !== '') {
            // deny, ban, list or shared
        } elseif (!empty($rules['probes']) && self::isProbe($rules['probes'], $path)) {
            $rule = 'probe';
        } elseif (($matched = RequestRules::matchRequest(isset($rules['requests']) ? $rules['requests'] : array(), $method, $path, $userAgent))) {
            $rule = 'request:' . $matched['id'];
        } elseif ($rules['rate'] && !self::has(isset($rules['goodbots']) ? $rules['goodbots'] : array(), $key) && $this->overRate($who, $rules['rate'], self::isStatic($path))) {
            $rule = 'rate';
        } elseif (!empty($rules['challenge']) && Challenge::needed($rules['challenge'], $this->opt('secret'), $ip, $method, $path,
            $accept, $pass, null, isset($rules['goodbots']) ? $rules['goodbots'] : array())) {
            $rule = 'challenge';
        }
        if ($rule === '') {
            return $allow;
        }
        $mode = in_array($this->options['mode'], array('monitor', 'block'), true) ? $this->options['mode'] : $rules['mode'];
        // The browser check is not a mode matter: the collector sends it only
        // when the site is to be checked.
        $action = $mode === 'block' || $rule === 'challenge' ? 'block' : 'monitor';
        // A request rule the dashboard only watches passes even in block mode;
        // one that blocks also bans the address here, as a flood does.
        if (isset($matched) && $matched) {
            $action = $action === 'block' && $matched['action'] === 'block' ? 'block' : 'monitor';
            if ($action === 'block' && $matched['ban']) {
                $this->banHere($who, $matched['ban']);
            }
        }
        // Asking for a secret file: banned here (with APCu); the report bans it on the site's other servers.
        if ($rule === 'probe' && $action === 'block') {
            $this->banHere($who, $rules['probes']['ban']);
        }
        // Over the rate limit: the same, banned here only in block mode.
        if ($rule === 'rate' && $action === 'block') {
            $this->banHere($who, isset($rules['ban']) ? $rules['ban'] : 0);
        }
        $event = function ($rule, $action) use ($ip, $method, $path, $userAgent) {
            return array(
                'at' => gmdate('Y-m-d\TH:i:s\Z'),
                'ip' => (string) $ip,
                'rule' => $rule,
                'action' => $action,
                'method' => substr((string) $method, 0, 10),
                'path' => substr(explode('?', (string) $path, 2)[0], 0, 300),
                'user_agent' => substr((string) $userAgent, 0, 300),
            );
        };
        // A match that is only watched (monitor) still gets the check: firewall.md, step 7.
        if ($action === 'monitor' && !empty($rules['challenge']) && Challenge::needed($rules['challenge'], $this->opt('secret'), $ip, $method,
            $path, $accept, $pass, null, isset($rules['goodbots']) ? $rules['goodbots'] : array())) {
            $this->report($event($rule, $action));
            $rule = 'challenge';
            $action = 'block';
        }
        $this->report($event($rule, $action));
        return array('action' => $action, 'rule' => $rule, 'status' => $rule === 'rate' ? 429 : ($rule === 'challenge' ? 503 : 403));
    }

    // The rules about the address alone (deny, bans, lists, shared): '' when none.
    private function addressRule(array $rules, $key, $who)
    {
        if (self::has($rules['deny'], $key)) {
            return 'deny';
        }
        if ((isset($rules['banned']) && self::has($rules['banned'], $key)) || $this->bannedHere($who)) {
            return 'ban';
        }
        if (self::has($rules['lists'], $key)) {
            return 'list';
        }
        return self::has($rules['shared'], $key) ? 'shared' : '';
    }

    // The address rules only, for the tracker's own addresses (the proxy): a
    // denied or banned address gets nothing from us either, but beacons are
    // never rate-limited, checked or matched against request rules. The same
    // shape as check().
    public function checkAddress($ip, $method = '', $path = '', $userAgent = '')
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
        $rule = $this->addressRule($rules, $key, self::who($ip));
        if ($rule === '') {
            return $allow;
        }
        $mode = in_array($this->options['mode'], array('monitor', 'block'), true) ? $this->options['mode'] : $rules['mode'];
        $action = $mode === 'block' ? 'block' : 'monitor';
        $this->report(array(
            'at' => gmdate('Y-m-d\TH:i:s\Z'),
            'ip' => (string) $ip,
            'rule' => $rule,
            'action' => $action,
            'method' => substr((string) $method, 0, 10),
            'path' => substr(explode('?', (string) $path, 2)[0], 0, 300),
            'user_agent' => substr((string) $userAgent, 0, 300),
        ));
        return array('action' => $action, 'rule' => $rule, 'status' => 403);
    }

    // The browser check's page for this address: array('status', 'headers',
    // 'body'), for a framework to answer with when check() says 'challenge'.
    public function challengePage($ip, $method = 'GET')
    {
        return Challenge::page($this->opt('secret'), $ip, $method);
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
            'challenge' => !empty($rules['challenge']),
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

    // "1.2.3.0/24" -> array(start, end) as ipKey()s; null when invalid, or
    // when an IPv6 range covers all of IPv4 (below).
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
        $start = bin2hex($start);
        $end = bin2hex($end);
        // An IPv6 range wide enough to hold all of ::ffff:0:0/96 (::/64,
        // ::/0) would, with IPv4 kept as ::ffff:a.b.c.d, match every IPv4
        // visitor: a /64 is one machine in IPv6, but here it is the whole
        // IPv4 internet. Dropped, whichever list it is in.
        if (!$v4 && strcmp($start, self::MAPPED_START) <= 0 && strcmp($end, self::MAPPED_END) >= 0) {
            return null;
        }
        return array($start, $end);
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
    // Also as the router would see it (RequestRules::routedPath(): no
    // ";params", "." and ".." resolved, decoded once), so "/x;y/../.env" is
    // the probe "/.env" too.
    public static function isProbe(array $probes, $path)
    {
        $raw = explode('?', (string) $path, 2)[0];
        $plain = strtolower(preg_replace('#/{2,}#', '/', $raw));
        $routed = RequestRules::routedPath(substr($raw, 0, RequestRules::MAX_TEXT));
        foreach ($plain === $routed ? array($plain) : array($plain, $routed) as $text) {
            if (isset($probes['exact'][$text])) {
                return true;
            }
            foreach ($probes['prefix'] as $prefix) {
                if (strpos($text, $prefix) === 0) {
                    return true;
                }
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
            // The browser check (flood protection): null unless the site is to be checked.
            'challenge' => Challenge::compile(isset($data['challenge']) ? $data['challenge'] : null),
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
        // What this server runs (the package's firewall and its browser
        // check) and its name, shown per server on the dashboard.
        $headers = array('X-Firewall-Layers: app check', 'X-Server-Name: ' . $this->serverName());
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

    // The server_name option, else the host name, as the check-in sends it;
    // 100 characters at most, on one line.
    public function serverName()
    {
        $name = $this->opt('server_name');
        if (empty($name)) {
            $name = function_exists('gethostname') ? (string) gethostname() : '';
        }
        return substr(trim(preg_replace('/[\x00-\x1f\x7f]+/', ' ', (string) $name)), 0, 100);
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

    // $who: who() of the address (an IPv4 address or an IPv6 /64).
    private function bannedHere($who)
    {
        return $who !== null && $this->apcu() && apcu_fetch('afw:ban:' . $this->opt('site_id') . ':' . $who) !== false;
    }

    private function banHere($who, $seconds)
    {
        if ($who !== null && $seconds > 0 && $this->apcu()) {
            apcu_store('afw:ban:' . $this->opt('site_id') . ':' . $who, 1, (int) $seconds);
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
            $who = self::who($ip);
            if ($login && $this->apcu()) {
                $name = 'afw:login:' . $this->opt('site_id') . ':' . $who;
                apcu_add($name, 0, max(60, $login['window']));
                if ((int) apcu_inc($name) >= $login['limit']) {
                    apcu_delete($name);
                    $this->banHere($who, $login['ban']);
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

    // Whether $who is over the limit. A static file isn't counted (it is
    // only compared with the count so far, where the counter can tell it
    // without adding one); countStatic() adds it after the response when it
    // answered an error.
    private function overRate($who, array $rate, $static = false)
    {
        if ($who === null) {
            return false;
        }
        $window = (int) floor(time() / $rate['window']);
        $name = 'afw:' . $this->opt('site_id') . ':' . $who . ':' . $window;
        $ttl = $rate['window'] * 2;
        if ($static) {
            $this->staticHit = array($name, $ttl);
            $hits = !is_callable($this->options['counter']) && $this->apcu() ? (int) apcu_fetch($name) : 0;
        } elseif (is_callable($this->options['counter'])) {
            $hits = (int) call_user_func($this->options['counter'], $name, $ttl);
        } elseif ($this->apcu()) {
            apcu_add($name, 0, $ttl);
            $hits = (int) apcu_inc($name);
        } else {
            return false;
        }
        return $hits > $rate['limit'];
    }

    // After the response: a static file that answered an error (404, 5xx)
    // counts against the rate limit after all, so a flood of made-up file
    // names that each boot the whole app is still limited. $status: the
    // response's (default http_response_code()).
    public function countStatic($status = null)
    {
        $hit = $this->staticHit;
        $this->staticHit = null;
        $status = $status === null ? (int) http_response_code() : (int) $status;
        if ($hit === null || $status < 400) {
            return;
        }
        try {
            if (is_callable($this->options['counter'])) {
                call_user_func($this->options['counter'], $hit[0], $hit[1]);
            } elseif ($this->apcu()) {
                apcu_add($hit[0], 0, $hit[1]);
                apcu_inc($hit[0]);
            }
        } catch (\Throwable $e) {
            // never break the site
        }
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
            $this->core->within(Core::DEADLINE, function () {
                $this->syncAndFlush();
            });
        } catch (\Throwable $e) {
            // never break the site
        }
    }

    private function syncAndFlush()
    {
        try {
            $this->countStatic();
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
