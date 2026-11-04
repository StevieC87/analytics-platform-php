<?php
// What the reviews of the newer packages found, checked here too: forwarded
// addresses with a port, counters a /64 can't dodge, Server speed and crawler
// rows a visitor can't multiply, the proxy's breaker, one deadline after the
// response, static files and the rate limit, passes in a second Cookie header,
// payloads JSON can't hold, paths a router normalises, and patterns PCRE
// reads differently from the rules' subset.
//
//   php test/HardeningTest.php

foreach (array('Core', 'RequestRules', 'Challenge', 'Firewall', 'Errors', 'Analytics', 'Audit', 'Performance', 'Crawlers', 'Flags', 'Proxy', 'Platform') as $class) {
    require_once __DIR__ . '/../src/' . $class . '.php';
}

use AnalyticsPlatform\Analytics;
use AnalyticsPlatform\Challenge;
use AnalyticsPlatform\Core;
use AnalyticsPlatform\Crawlers;
use AnalyticsPlatform\Errors;
use AnalyticsPlatform\Firewall;
use AnalyticsPlatform\Flags;
use AnalyticsPlatform\Performance;
use AnalyticsPlatform\Platform;
use AnalyticsPlatform\Proxy;
use AnalyticsPlatform\RequestRules;

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

$storage = sys_get_temp_dir() . '/analytics-hardening-test-' . getmypid();
// A closed port: every send fails at once, as a collector that's away.
$options = array('site_id' => 'a1b2c3d4e5f6a1b2c3d4e5f6', 'secret' => 's', 'endpoint' => 'http://127.0.0.1:1', 'storage' => $storage);

function lines($file)
{
    return is_file($file) ? array_map(function ($l) {
        return json_decode($l, true);
    }, file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES)) : array();
}

// ---- 1. Forwarded addresses ---------------------------------------------------

$server = array('REMOTE_ADDR' => '10.0.0.2');
foreach (array(
    '203.0.113.5:54321' => '203.0.113.5',
    '[2001:db8::1]:443' => '2001:db8::1',
    '[2001:db8::1]' => '2001:db8::1',
    '2001:db8::1' => '2001:db8::1',
    ' 198.51.100.4 ' => '198.51.100.4',
) as $hop => $want) {
    $server['HTTP_X_FORWARDED_FOR'] = '192.0.2.1, ' . $hop;
    check("the hop $hop is read as $want", Firewall::clientIpFrom($server, 1) === $want);
}
foreach (array('unknown', 'evil.example', '1.2.3', '999.1.1.1:80', '_hidden') as $junk) {
    $server['HTTP_X_FORWARDED_FOR'] = '192.0.2.1, ' . $junk;
    check("a hop that isn't an address ($junk) falls back to the connection", Firewall::clientIpFrom($server, 1) === '10.0.0.2');
}
$server['HTTP_X_FORWARDED_FOR'] = '198.51.100.4';
check('more proxies than hops: the leftmost', Firewall::clientIpFrom($server, 3) === '198.51.100.4');
check('trust_proxy 0 never reads the header', Firewall::clientIpFrom($server, 0) === '10.0.0.2');
$cf = array('REMOTE_ADDR' => '172.68.10.20', 'HTTP_CF_CONNECTING_IP' => 'not-an-address');
check('a CF-Connecting-IP that is no address is not believed', Firewall::clientIpFrom($cf, 'cloudflare') === '172.68.10.20');
$cf['HTTP_CF_CONNECTING_IP'] = '[2001:db8::7]:1';
check('and one with a port loses it', Firewall::clientIpFrom($cf, 'cloudflare') === '2001:db8::7');

// ---- 3. Counters by /64, ::ffff as IPv4 ---------------------------------------

check('IPv6 counts by its /64', Firewall::who('2001:db8:0:1::9') === '2001:db8:0:1::/64'
    && Firewall::who('2001:db8:0:1:ffff:1:2:3') === '2001:db8:0:1::/64');
check('IPv4-mapped IPv6 counts as IPv4', Firewall::who('::ffff:203.0.113.9') === '203.0.113.9');
check('IPv4 as itself', Firewall::who('203.0.113.9') === '203.0.113.9');
check('no address, no key', Firewall::who('nope') === null);

$keys = array();
$counter = function ($key, $ttl) use (&$keys) {
    $keys[] = $key;
    return count(array_keys($keys, $key));
};
$firewall = new Firewall($options + array('counter' => $counter));
$core = new Core($options);
$core->ensureDir();
$rules = array('v' => 1, 'etag' => '', 'fetched' => time(), 'enabled' => true, 'mode' => 'block', 'sync' => 60,
    'rate' => array('limit' => 2, 'window' => 60), 'ban' => 0, 'login' => null, 'probes' => Firewall::compileProbes(array('exact' => array('/.env'), 'ban' => 0)),
    'requests' => RequestRules::compile(array('rules' => array(array('id' => 'admin', 'action' => 'block', 'path' => array('prefix' => array('/admin')))))),
    'challenge' => null);
foreach (Firewall::RULES as $list) {
    $rules[$list] = array();
}
$core->writePhp('rules.php', $rules);

$firewall->check('2001:db8:0:1::1', 'GET', '/');
$firewall->check('2001:db8:0:1::2', 'GET', '/');
$third = $firewall->check('2001:db8:0:1::3', 'GET', '/');
check('three addresses of one /64 share one count', count(array_unique($keys)) === 1 && $third['rule'] === 'rate');

// ---- 7. Static files and the rate limit ----------------------------------------

$keys = array();
$firewall = new Firewall($options + array('counter' => $counter));
$asset = $firewall->check('198.51.100.20', 'GET', '/app.css?v=3');
check('a static file is not counted', $keys === array() && $asset['action'] === 'allow');
$firewall->countStatic(200);
check('nor after it was served', $keys === array());
$firewall->check('198.51.100.20', 'GET', '/made-up.woff2');
$firewall->countStatic(404);
check('but one that answered 404 is', count($keys) === 1);
$firewall->check('198.51.100.20', 'GET', '/');
check('a page is counted as before', count($keys) === 2);
check('static by extension, query left out', Firewall::isStatic('/a/b.JPG?x=1') && !Firewall::isStatic('/style.css.php') && !Firewall::isStatic("/a.css\n"));

// ---- 11. Paths a router normalises ----------------------------------------------

foreach (array(
    '/x;y/../admin' => '/admin',
    '/x/..;/admin/' => '/admin/',
    '/x/..%2fadmin' => '/admin',
    '/./admin' => '/admin',
    '/../../admin' => '/admin',
    '/a/b/..' => '/a/',
    '/ADMIN;jsessionid=1' => '/admin',
) as $path => $want) {
    check("$path is routed as $want", RequestRules::routedPath($path) === $want);
}
$compiled = $rules['requests'];
check('a prefix rule matches the routed path', RequestRules::matchRequest($compiled, 'GET', '/x;y/../admin/users?q=1', '') !== null);
check('and still the plain one', RequestRules::matchRequest($compiled, 'GET', '/admin', '') !== null);
check('and not a path that never gets there', RequestRules::matchRequest($compiled, 'GET', '/x/admin', '') === null);
check('a probe behind a ;param or dot segment is a probe', Firewall::isProbe($rules['probes'], '/x;y/../.env') && Firewall::isProbe($rules['probes'], '/a/./../.ENV'));

// ---- 16. Patterns outside the shared subset --------------------------------------

foreach (array('(?i)admin', '(?>a+)b', '(?R)', '(a)(?1)', '(?&x)', '(*SKIP)a', '(*UTF)a', 'a++b', 'a*+b', 'a?+b', 'a{2}+b',
    '(a)\\g{1}', '(a)\\g1', '\\k<x>', '(?P<x>a)', '(?<x>a)', "(?'x'a)", '(?P=x)', '\\Qa+\\E', '(?(1)a|b)', '(?|a|b)', '(?#c)a', '(?<=a)b', '(?<!a)b') as $pattern) {
    check("refuses $pattern", !RequestRules::safePattern($pattern));
}
foreach (array('a+?b', '(?:ab)c', '(?=a)a', '(?!a)b', 'a\\+b', '\\\\+b', '\\d{2,4}x', '[+*]+x') as $pattern) {
    check("allows $pattern", RequestRules::safePattern($pattern));
}

// ---- 8. A pass in a second Cookie header ---------------------------------------

check('a pass after a comma counts', Challenge::cookieValues('a=1, __sg_pass=20000.abc; b=2') === array('20000.abc'));
check('every Cookie header of a framework, joined', Challenge::cookieHeaderOf(array('cookie' => array('a=1', '__sg_pass=x'), 'accept' => array('*/*'))) === 'a=1; __sg_pass=x');
check('any case', Challenge::cookieHeaderOf(array('Cookie' => 'a=1')) === 'a=1');

// ---- 4 and 17. Rows a visitor can't multiply ------------------------------------

check('known methods stay', Performance::method('post') === 'POST' && Performance::method('JOB') === 'JOB');
check('any other is OTHER', Performance::method('BREW') === 'OTHER' && Performance::method("GET\n") === 'GET' && Performance::method('') === 'OTHER');
$perf = new Performance($core);
for ($i = 0; $i < 2000; $i++) {
    $core->append('requests', array('t' => time(), 'm' => 'M' . $i, 'r' => '/r' . $i, 's' => 200 + ($i % 300), 'd' => 1), 10000000);
}
$perf->flush(true);
$rows = array();
foreach (lines($core->dir() . '/requests.retry.jsonl') as $batch) {
    $rows = array_merge($rows, $batch['body']['rows']);
}
$methods = array_unique(array_map(function ($r) {
    return $r['method'];
}, $rows));
check('made-up methods are one OTHER', $methods === array('OTHER'));
check('Server speed rows stop at the hard cap', count($rows) > 0 && count($rows) <= Performance::HARD_MAX_KEYS);
@unlink($core->dir() . '/requests.retry.jsonl');

$crawlers = new Crawlers($core);
for ($i = 0; $i < 2000; $i++) {
    $core->append('crawlers', array('t' => time(), 'b' => 'Bot' . ($i % 50), 'p' => '/p' . $i, 's' => 200 + ($i % 40), 'z' => 1, 'd' => 1), 10000000);
}
$crawlers->flush(true);
$rows = array();
foreach (lines($core->dir() . '/crawlers.retry.jsonl') as $batch) {
    $rows = array_merge($rows, $batch['body']['rows']);
}
check('crawler rows stop at the hard cap', count($rows) > 0 && count($rows) <= Crawlers::HARD_MAX_KEYS);
@unlink($core->dir() . '/crawlers.retry.jsonl');

// ---- 6. One deadline; the spool kept until it was sent ----------------------------

$started = microtime(true);
$res = $core->within(0, function () use ($core) {
    return $core->post('errors', '/events/server-errors', array('errors' => array(array('message' => 'late'))));
});
check('past the deadline nothing is sent', $res['status'] === 0 && microtime(true) - $started < 0.5);
check('and the batch waits to be sent later', count(lines($core->dir() . '/errors.retry.jsonl')) === 1);
check('the deadline ends with within()', $core->timeLeft() === null);
$core->within(5, function () use ($core) {
    $core->within(60, function () use ($core) {
        check('a nested deadline keeps the earlier end', $core->timeLeft() <= 5);
    });
});

// A request killed while sending left the file it had taken.
$retry = $core->dir() . '/errors.retry.jsonl';
rename($retry, $retry . '.sending');
check('a left-behind file counts as waiting', $core->waiting('errors'));
$core->drain('errors', 0, true, function () {
});
check('the next run sends it again (here: keeps it, the collector is away)', count(lines($retry)) === 1 && !is_file($retry . '.sending'));
@unlink($retry);

// ---- 10. Payloads JSON can't hold ------------------------------------------------

$handle = fopen('php://memory', 'r');
$plain = Core::plain(array('a' => 1, 'f' => $handle, 'n' => NAN, 'nested' => array('ok' => 'yes'), 'bad' => "\xff"));
check('what JSON can hold stays', is_array($plain) && $plain['a'] === 1 && $plain['nested'] === array('ok' => 'yes'));
check('what it cannot becomes null (NAN: 0, as PHP writes it)', $plain['f'] === null && $plain['n'] === 0 && json_encode($plain) !== false);
$analytics = new Analytics($core);
$uid = $analytics->track('purchase', array('numeric_value' => 9.5, 'meta' => $handle));
check('track() takes a field JSON cannot hold', $uid !== '');
$unsendable = $core->post('analytics', '/events/server-events', array('events' => array(array('n' => NAN))));
check('a body JSON cannot write is not a network failure', $unsendable['status'] === Core::UNSENDABLE);
check('and is not kept to be sent again', !is_file($core->dir() . '/analytics.retry.jsonl'));
$analytics->flush();
$kept = lines($core->dir() . '/analytics.retry.jsonl');
check('the converted event is sent (kept here, the collector is away)', count($kept) === 1 && $kept[0]['body']['events'][0]['meta'] === null);
@unlink($core->dir() . '/analytics.retry.jsonl');

// ---- 12. Message cap, spool size with the line ---------------------------------

check('a message is cut to 2,000 characters', mb_strlen(Errors::cut(str_repeat('é', 5000)), 'UTF-8') === 2000);
check('a short one is left alone', Errors::cut('short') === 'short');
$core->append('cap', array('x' => str_repeat('a', 50)), 1000);
check('a line that would take the spool past its size is refused', !$core->append('cap', array('x' => str_repeat('a', 2000)), 1000));
check('one that fits is kept', $core->append('cap', array('x' => 'b'), 1000));
@unlink($core->dir() . '/cap.jsonl');

// ---- 9. A visitor who went away --------------------------------------------------

check('a broken pipe is recognised', (bool) preg_match(Errors::GONE, 'fwrite(): Send of 8192 bytes failed with errno=32 Broken pipe'));
check('but only once PHP says the visitor is gone', !Errors::clientGone(new \ErrorException('Broken pipe')));

// ---- 13. The preview cookie ---------------------------------------------------------

check('Secure over https', Flags::cookieOptions(true)['secure'] === true && Flags::cookieOptions(false)['secure'] === false);
check('never for scripts', Flags::cookieOptions(true)['httponly'] === true);

// ---- 15. A trailing newline is not a match ------------------------------------------

check('a site id with a newline is not configured', !(new Core(array('site_id' => "a1b2c3d4e5f6a1b2c3d4e5f6\n") + $options))->configured());
$_SERVER['HTTP_X_ANALYTICS_SESSION'] = "12345678-1234-1234-1234-123456789abc\n";
check('nor a session id', Platform::sessionIdFromRequest() === '');
unset($_SERVER['HTTP_X_ANALYTICS_SESSION']);
$proxy = new Proxy('http://127.0.0.1:1', 's3cret', $core->dir());
check('nor a proxied path', $proxy->match('/' . $proxy->prefix() . "/js/v1/s.js\n") === array('bad', ''));

// ---- 5. The proxy's breaker ---------------------------------------------------------

$beacon = function () use ($proxy) {
    return $proxy->handle('api', 'e', 'POST', '', array(), '{}', '203.0.113.9');
};
for ($i = 0; $i < Proxy::BREAKER_FAILURES; $i++) {
    $answer = $beacon();
}
check('a collector that is away answers 502', $answer['status'] === 502);
check('after three failures it is left alone', $proxy->resting());
$started = microtime(true);
$answer = $beacon();
check('beacons are answered at once, with Retry-After', $answer['status'] === 502 && isset($answer['headers']['Retry-After'])
    && microtime(true) - $started < 0.2);
$started = microtime(true);
$file = $proxy->handle('js', 'v1/s.js');
check('the tracker file is not fetched while it rests', $file['status'] === 502 && microtime(true) - $started < 0.2);
@unlink($core->dir() . '/px-breaker.json');
$proxy->handle('js', 'v1/track.js');
check('a failed file fetch is remembered', (function_exists('apcu_enabled') && apcu_enabled())
    || is_file($core->dir() . '/px-' . hash('sha256', 'v1/track.js') . '.failed'));
$started = microtime(true);
$again = $proxy->handle('js', 'v1/track.js');
check('and not fetched again straight away', $again['status'] === 502 && microtime(true) - $started < 0.2);
@unlink($core->dir() . '/px-breaker.json');

// ---- 5. Deny and bans before the proxy --------------------------------------------

$rules['deny'] = Firewall::compileList(array('198.51.100.66'));
$core->writePhp('rules.php', $rules);
$_SERVER['REQUEST_METHOD'] = 'POST';
$platform = new Platform($options + array('firewall' => array(), 'errors' => false, 'performance' => false, 'crawlers' => false, 'resources' => false, 'inventory' => false));
$denied = $platform->proxyResponse('/' . $platform->proxy()->prefix() . '/api/e', 'POST', '', array(), '{}', '198.51.100.66');
check('a denied address gets nothing from the proxy', $denied !== null && $denied['status'] === 403);
$events = lines($core->dir() . '/events.jsonl');
check('and is reported', $events && end($events)['rule'] === 'deny');
@unlink($core->dir() . '/px-breaker.json');
$keys = array();
$rate = new Firewall($options + array('counter' => $counter));
check('the proxy check is the address only, never the rate', $rate->checkAddress('203.0.113.77', 'POST', '/x/api/e')['action'] === 'allow' && $keys === array());

// ---- 3. Bans and failed logins by /64, with APCu (where it is loaded) ------------

if (function_exists('apcu_enabled') && apcu_enabled()) {
    $rules['deny'] = array();
    $rules['probes'] = Firewall::compileProbes(array('exact' => array('/.env'), 'ban' => 600));
    $rules['login'] = array('limit' => 2, 'window' => 3600, 'ban' => 600);
    $rules['rate'] = array('limit' => 1000, 'window' => 60);
    $core->writePhp('rules.php', $rules);
    $apcu = new Firewall($options);
    $apcu->check('2001:db8:0:2::1', 'GET', '/.env');
    check('a probe bans its whole /64', $apcu->check('2001:db8:0:2::ffff', 'GET', '/')['rule'] === 'ban');
    check('not the next /64', $apcu->check('2001:db8:0:3::1', 'GET', '/')['rule'] === '');
    $apcu->loginFailed('2001:db8:0:4::1');
    $apcu->loginFailed('2001:db8:0:4::2');
    check('failed logins count by /64', $apcu->check('2001:db8:0:4::3', 'GET', '/')['rule'] === 'ban');
    $apcu->check('::ffff:198.51.100.80', 'GET', '/.env');
    check('a mapped address is banned as its IPv4', $apcu->check('198.51.100.80', 'GET', '/')['rule'] === 'ban');
    $apcuProxy = new Proxy('http://127.0.0.1:1', 'other-secret', '');
    for ($i = 0; $i < Proxy::BREAKER_FAILURES; $i++) {
        $apcuProxy->handle('api', 'e', 'POST', '', array(), '{}', '203.0.113.9');
    }
    check('the breaker lives in APCu without a folder', $apcuProxy->resting());
} else {
    echo "SKIP: APCu isn't loaded, so bans and the breaker in APCu aren't checked\n";
}

// The shared counter's key: the same text in every package, so a site
// mixing languages on one Redis counts a visitor once.
check('counter key: IPv4', Firewall::who('198.51.100.7') === '198.51.100.7');
check('counter key: mapped IPv4 is IPv4', Firewall::who('::ffff:198.51.100.7') === '198.51.100.7');
check('counter key: the /64 as its network, compressed', Firewall::who('2001:db8:1:2:aa::1') === '2001:db8:1:2::/64');
check('counter key: zero groups compressed', Firewall::who('2001:0:0:0:5::') === '2001::/64');

// Dashboard headers: visible ASCII values, never a framing header.
check('a security header is kept', Core::safeHeader(array('X-Frame-Options', 'DENY')));
check('a tab in a value is fine', Core::safeHeader(array('Content-Security-Policy', "default-src\t'self'")));
check('a curly quote is refused', !Core::safeHeader(array('Content-Security-Policy', "default-src \xe2\x80\x98self\xe2\x80\x99")));
check('a control character is refused', !Core::safeHeader(array('X-A', "a\x01b")));
check('a line break is refused', !Core::safeHeader(array('X-A', "a\nSet-Cookie: x=1")));
foreach (array('Content-Length', 'transfer-encoding', 'Connection', 'Set-Cookie', 'Content-Type') as $name) {
    check("$name is refused", !Core::safeHeader(array($name, '1')));
}

foreach (glob($core->dir() . '/*') ?: array() as $path) {
    @unlink($path);
}
@rmdir($core->dir());
@rmdir($storage);

echo ($failed ? "FAILED" : "OK") . ": $checked checks, $failed failed\n";
exit($failed ? 1 : 0);
