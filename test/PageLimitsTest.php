<?php
// Page limits (firewall.md, "Page limits" and step 6 of "Checking a
// request"), against the cases every client shares:
// sdk/protocols/page-limits-cases.json. Then what the cases leave to each
// client: a window ending, the 429 itself, the counter keys, no counter at all.
//
//   php test/PageLimitsTest.php
// (No dependencies: the package has none, so this is plain PHP, not PHPUnit.)

require __DIR__ . '/../src/Core.php';
require __DIR__ . '/../src/RequestRules.php';
require __DIR__ . '/../src/Challenge.php';
require __DIR__ . '/../src/Firewall.php';

use AnalyticsPlatform\Core;
use AnalyticsPlatform\Firewall;

// Not copied in: a copy would drift from the other clients' without a sound.
$casesFile = __DIR__ . '/../../protocols/page-limits-cases.json';
if (!is_file($casesFile)) {
    echo "SKIP: the shared protocol fixtures are not alongside this package\n";
    exit(0);
}
$cases = json_decode((string) file_get_contents($casesFile), true);
if (!is_array($cases) || empty($cases['scenarios'])) {
    fwrite(STDERR, "Could not read the shared cases.\n");
    exit(1);
}

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

// The rules arrive as the collector sends them, through sync().
class LimitsCore extends Core
{
    public $answer = array();

    public function http($method, $path, $body = null, array $headers = array(), $auth = 'bearer')
    {
        return array('status' => 200, 'body' => json_encode($this->answer), 'headers' => array('etag' => '"1"'));
    }
}

// APCu stands in as an array: the plain PHP these tests run on has none.
class LocalFirewall extends Firewall
{
    public $local = array();

    protected function countHere($name, $ttl)
    {
        $this->local[$name] = (isset($this->local[$name]) ? $this->local[$name] : 0) + 1;
        return $this->local[$name];
    }
}

$store = sys_get_temp_dir() . '/analytics-limits-test-' . getmypid();
$options = array('site_id' => 'a1b2c3d4e5f6a1b2c3d4e5f6', 'secret' => 's', 'endpoint' => 'http://127.0.0.1:9', 'storage' => $store);

// A fresh firewall on these rules: no counts, no bans. $shared holds the
// shared counter's keys, one entry per hit; $class LocalFirewall or not.
function wall(array $answer, &$shared, $class = 'LocalFirewall', $counter = true)
{
    global $options;
    $shared = array();
    $core = new LimitsCore($options);
    $core->answer = $answer;
    $opts = $options;
    if ($counter) {
        $opts['counter'] = function ($key, $ttl) use (&$shared) {
            $shared[] = $key;
            return count(array_keys($shared, $key));
        };
    }
    $wall = new $class($opts, $core);
    $wall->sync(true);
    @unlink($core->dir() . '/events.jsonl');
    return array($wall, $core);
}

// The rules this request reported (and clears them).
function reported(Core $core)
{
    $file = $core->dir() . '/events.jsonl';
    $rows = is_file($file) ? array_map(function ($line) {
        return json_decode($line, true)['rule'];
    }, file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES)) : array();
    @unlink($file);
    sort($rows);
    return $rows;
}

// ---- The shared cases ---------------------------------------------------------

foreach ($cases['scenarios'] as $scenario) {
    $answer = array_merge($cases['base'], isset($scenario['rules']) ? $scenario['rules'] : array());
    $answer['limits'] = $scenario['limits'];
    list($wall, $core) = wall($answer, $shared);
    foreach ($scenario['requests'] as $i => $request) {
        $got = $wall->check($request['ip'], $request['method'], $request['target']);
        $want = $request['expect'];
        $label = sprintf('%s, request %d (%s %s %s)%s', $scenario['name'], $i + 1, $request['ip'], $request['method'], $request['target'],
            isset($request['why']) ? ': ' . $request['why'] : '');
        if ($want === 'allow') {
            check($label . ' passes', $got['action'] === 'allow');
        } else {
            check($label . ' is ' . json_encode($want) . ', got ' . json_encode($got),
                $got['action'] === $want['action'] && $got['rule'] === $want['rule'] && $got['status'] === $want['status']);
        }
        $reports = isset($request['reports']) ? $request['reports'] : ($want === 'allow' ? array() : array($want['rule']));
        sort($reports);
        $sent = reported($core);
        check($label . ' reports ' . json_encode($reports) . ', got ' . json_encode($sent), $sent === $reports);
    }
}

// ---- Counter keys ---------------------------------------------------------------

$login = array('id' => 'wp.login', 'action' => 'block', 'limit' => 1, 'window' => 60, 'methods' => array('POST'), 'path' => array('exact' => array('/wp-login.php')));
$every = array('id' => 'any', 'action' => 'block', 'limit' => 5, 'window' => 600, 'each' => 'path', 'path' => array('prefix' => array('/')));
list($wall, $core) = wall(array_merge($cases['base'], array('limits' => array('rules' => array($login, $every)))), $shared);
$wall->check('2001:db8:1:2::1', 'POST', '/wp-login.php');
check('the shared counter is keyed afw:<site_id>:l:<id>:<who>:<window>',
    $shared === array('afw:a1b2c3d4e5f6a1b2c3d4e5f6:l:wp.login:2001:db8:1:2::/64:' . (int) floor(time() / 60)));
check('a count per page stays on this server', count($wall->local) === 1
    && strpos(key($wall->local), 'afw:a1b2c3d4e5f6a1b2c3d4e5f6:l:any:2001:db8:1:2::/64:') === 0);

// ---- No counter: page limits don't count, as the rate limit doesn't -----------

list($plain, $core) = wall(array_merge($cases['base'], array('limits' => array('rules' => array($login)))), $shared, 'AnalyticsPlatform\\Firewall', false);
if (function_exists('apcu_enabled') && apcu_enabled()) {
    echo "SKIP: APCu is loaded, so there is no running without a counter\n";
} else {
    $plain->check('198.51.100.7', 'POST', '/wp-login.php');
    check('without a counter nothing is limited', $plain->check('198.51.100.7', 'POST', '/wp-login.php')['action'] === 'allow');
}
// A shared counter but no APCu: the limit for every page has nowhere to count.
list($remote, $core) = wall(array_merge($cases['base'], array('limits' => array('rules' => array(array('limit' => 1) + $every)))), $shared, 'AnalyticsPlatform\\Firewall');
if (!(function_exists('apcu_enabled') && apcu_enabled())) {
    $remote->check('198.51.100.7', 'GET', '/a');
    check('a count per page never goes to the shared counter', $remote->check('198.51.100.7', 'GET', '/a')['action'] === 'allow' && $shared === array());
}

// ---- The 429 ----------------------------------------------------------------------

$slow = array('window' => 90) + $login;
list($wall, $core) = wall(array_merge($cases['base'], array('limits' => array('rules' => array($slow)), 'rate' => array('limit' => 1000, 'window' => 60))), $shared);
$wall->check('198.51.100.7', 'POST', '/wp-login.php');
$decision = $wall->check('198.51.100.7', 'POST', '/wp-login.php');
$answer = $wall->blockedResponse($decision);
check('a blocking limit answers 429', $decision['rule'] === 'limit:wp.login' && $answer['status'] === 429);
check('with Retry-After: its own window', isset($answer['headers']['Retry-After']) && $answer['headers']['Retry-After'] === '90');
check('and the plain-text body', $answer['body'] === 'Too many requests to this page. Please wait a little and try again.'
    && $answer['headers']['Content-Type'] === 'text/plain; charset=utf-8');
check('a page limit bans nobody', $wall->check('198.51.100.7', 'GET', '/')['action'] === 'allow');
$rate = $wall->blockedResponse(array('action' => 'block', 'rule' => 'rate', 'status' => 429));
check('the rate limit keeps its own answer', $rate['body'] === 'Too Many Requests' && $rate['headers']['Retry-After'] === '60');

// ---- A window ending ----------------------------------------------------------------

$quick = array('window' => 1) + $login;
list($wall, $core) = wall(array_merge($cases['base'], array('limits' => array('rules' => array($quick)))), $shared);
// Both requests inside one second, then the next second is a new window.
time_sleep_until(floor(microtime(true)) + 1.01);
$wall->check('198.51.100.7', 'POST', '/wp-login.php');
check('over the limit inside the window', $wall->check('198.51.100.7', 'POST', '/wp-login.php')['rule'] === 'limit:wp.login');
time_sleep_until(floor(microtime(true)) + 1.01);
check('a new window starts a new count', $wall->check('198.51.100.7', 'POST', '/wp-login.php')['action'] === 'allow');

// ---- Static files: tricks count, real assets don't -------------------------------

// Tricks that would make a page read as a static file, so a flood of them
// skips the rate and the page limits, and real assets: the cases every
// package shares (sdk/protocols/static-cases.json, firewall.md, `rate`).
$notStatic = array();
$static = array();
foreach (json_decode((string) file_get_contents(__DIR__ . '/../../protocols/static-cases.json'), true)['cases'] as $case) {
    if (isset($case['only']) && !in_array('php', $case['only'], true)) {
        continue;
    }
    $request = array($case['path'], isset($case['method']) ? $case['method'] : 'GET');
    if ($case['static']) {
        $static[] = $request;
    } else {
        $notStatic[] = $request;
    }
}
foreach ($notStatic as list($target, $method)) {
    check('not a static file: ' . $method . ' ' . substr($target, 0, 60), !Firewall::isStatic($target, $method));
}
foreach ($static as list($target, $method)) {
    check('a static file: ' . $method . ' ' . $target, Firewall::isStatic($target, $method));
}
list($rate, $core) = wall(array_merge($cases['base'], array('rate' => array('limit' => 1, 'window' => 60), 'limits' => array('rules' => array()))), $shared);
list($limits) = wall(array_merge($cases['base'], array('limits' => array('rules' => array(
    array('id' => 'all', 'action' => 'block', 'limit' => 1, 'window' => 60, 'path' => array('prefix' => array('/'))))))), $shared);
foreach (array_merge($notStatic, $static) as $i => list($target, $method)) {
    $ip = '198.51.100.' . ($i + 1);
    $counted = $i < count($notStatic);
    $rate->check($ip, $method, $target);
    check('rate, ' . substr($target, 0, 60), $rate->check($ip, $method, $target)['rule'] === ($counted ? 'rate' : ''));
    $limits->check($ip, $method, $target);
    check('page limit, ' . substr($target, 0, 60), $limits->check($ip, $method, $target)['rule'] === ($counted ? 'limit:all' : ''));
}

foreach (array_merge(glob($core->dir() . '/*') ?: array(), glob($core->dir() . '/.[!.]*') ?: array()) as $path) {
    @unlink($path);
}
@rmdir($core->dir());
@rmdir($store);

echo ($failed ? "FAILED" : "OK") . ": $checked checks, $failed failed\n";
exit($failed ? 1 : 0);
