<?php
// The WordPress plugin's first-party proxy (wordpress-plugin/site-analytics/
// px.php). It is reached directly, without WordPress, so nothing else checks
// what it will forward: it decides on its own which addresses are allowed and
// where they go. A mistake here would let anyone use a customer's site to
// fetch whatever they liked, so what this test covers is the gate. The
// forwarding itself needs a collector and is checked by hand.
//
// px.php is run as the web server runs it, with the address in PATH_INFO
// (prefix first, which is how it knows whose config to read) and a config of
// our own. The collector is pointed at a closed port, so an
// allowed address fails upstream at once and answers with nothing, while a
// rejected one answers "Not found" without asking anybody.
//
//   php test/ProxyTest.php

require_once __DIR__ . '/../src/Proxy.php';

$px = realpath(__DIR__ . '/../../wordpress-plugin/site-analytics/px.php');
// Most of this file drives the plugin's px.php as a subprocess, so it only
// runs from the full tree. Published on its own, there is no plugin to drive.
if ($px === false) {
    echo "SKIP: the WordPress plugin is not alongside this package, so px.php cannot be driven\n";
    exit(0);
}
// The first place px.php looks (sdk/cache/site-analytics/px/<prefix>.php),
// never the plugin folder: a leftover there would be shipped in the zip.
$configDir = __DIR__ . '/../../cache/site-analytics/px';
$cacheDir = sys_get_temp_dir() . '/sa-proxy-test-' . getmypid();
@mkdir($configDir, 0777, true);
@mkdir($cacheDir, 0777, true);
// The plugin works the path out from the secret and writes it here, because
// the secret itself must never sit in a file the web server can serve.
$prefix = AnalyticsPlatform\Proxy::prefixFor('s3cret');
$configFile = $configDir . '/' . $prefix . '.php';
file_put_contents($configFile, "<?php\nreturn " . var_export(array(
    'endpoint' => 'http://127.0.0.1:1', 'trust_proxy' => '0', 'dir' => $cacheDir, 'prefix' => $prefix,
), true) . ";\n");

$failed = 0;
$checked = 0;
function check($name, $ok)
{
    global $failed, $checked;
    $checked++;
    if (!$ok) {
        $failed++;
        echo "FAIL: $name\n";
    }
}

// $pathInfo is below the prefix; $raw sends it exactly as given instead.
function run($px, $pathInfo, $method = 'GET', $raw = false)
{
    // Reached directly, so the address arrives as PATH_INFO, prefix first.
    global $prefix;
    $pathInfo = $raw ? $pathInfo : '/' . $prefix . $pathInfo;

    $command = 'REQUEST_METHOD=' . escapeshellarg($method)
        . ' PATH_INFO=' . escapeshellarg($pathInfo)
        . ' REMOTE_ADDR=203.0.113.9 QUERY_STRING='
        . ' php ' . escapeshellarg($px) . ' < /dev/null 2>&1';
    return (string) shell_exec($command);
}
$refused = function ($out) {
    return strpos($out, 'Not found') !== false;
};

// Only the two prefixes, and only tracker files we know by name.
foreach (array(
    '/' => 'no prefix',
    '/js/' => 'no file',
    '/other/v1/s.js' => 'an unknown prefix',
    '/js/v1/../../../wp-config.php' => 'a traversal',
    '/js/v1/evil.js' => 'an unknown file',
    '/js/../api/e' => 'a traversal into the collector',
    '/api/' => 'an empty collector path',
    '/js/v1/s.php' => 'a PHP file',
) as $path => $name) {
    check("rejects $name", $refused(run($px, $path)));
}

// The prefix picks the config, so it must be this site's and nothing else:
// another site's (or an old secret's) has no config here, and it is part of a
// file name, so nothing but eight hex digits gets that far.
foreach (array(
    '/js/v1/s.js' => 'no prefix at all',
    '/' . AnalyticsPlatform\Proxy::prefixFor('other') . '/js/v1/s.js' => "another site's prefix",
    '/../px/' . $prefix . '/js/v1/s.js' => 'a traversal in the prefix',
) as $path => $name) {
    check("rejects $name", $refused(run($px, $path, 'GET', true)));
}

// What is allowed gets as far as asking the collector, which isn't there.
foreach (array('/js/v1/s.js', '/js/v1.2.3/track.js', '/js/v1/replay.js', '/api/e', '/api/proxy-check') as $path) {
    check("allows $path", !$refused(run($px, $path, $path === '/api/e' ? 'POST' : 'GET')));
}

// Methods the tracker never uses are not forwarded.
foreach (array('PUT', 'DELETE') as $method) {
    check("rejects $method", $refused(run($px, '/api/e', $method)));
}

// Served from the on-disk copy when the collector can't be reached, so a blip
// at our end never leaves the site without its tracker.
file_put_contents($cacheDir . '/px-' . hash('sha256', 'v1/s.js') . '.js', str_repeat("// cached tracker\n", 60));
check('falls back to the cached tracker', strpos(run($px, '/js/v1/s.js'), 'cached tracker') !== false);

// A denied address gets nothing: px.php reads the firewall's rules from the
// storage folder (the config names the site, whose bans they are) before it
// forwards anything. run() connects from 203.0.113.9.
require_once __DIR__ . '/../src/Core.php';
require_once __DIR__ . '/../src/Firewall.php';
file_put_contents($configFile, "<?php\nreturn " . var_export(array(
    'endpoint' => 'http://127.0.0.1:1', 'trust_proxy' => '0', 'dir' => $cacheDir, 'prefix' => $prefix,
    'site_id' => 'a1b2c3d4e5f6a1b2c3d4e5f6',
), true) . ";\n");
$rules = array('v' => 1, 'etag' => '', 'fetched' => time(), 'enabled' => true, 'mode' => 'block', 'sync' => 60, 'rate' => null,
    'ban' => 0, 'login' => null, 'probes' => null, 'requests' => array(), 'challenge' => null);
foreach (AnalyticsPlatform\Firewall::RULES as $list) {
    $rules[$list] = AnalyticsPlatform\Firewall::compileList($list === 'deny' ? array('203.0.113.0/24') : array());
}
file_put_contents($cacheDir . '/rules.php', "<?php\nreturn " . var_export($rules, true) . ";\n");
$out = run($px, '/api/e', 'POST');
check('a denied address is refused before anything is forwarded', strpos($out, 'Forbidden') !== false);
check('and reported for the dashboard', strpos((string) @file_get_contents($cacheDir . '/events.jsonl'), '"rule":"deny"') !== false);
$rules['mode'] = 'monitor';
file_put_contents($cacheDir . '/rules.php', "<?php\nreturn " . var_export($rules, true) . ";\n");
check('in monitor mode it is only reported', strpos(run($px, '/api/e', 'POST'), 'Forbidden') === false);

foreach (array($configFile, $cacheDir . '/px-' . hash('sha256', 'v1/s.js') . '.js') as $path) {
    @unlink($path);
}
foreach (glob($cacheDir . '/*') ?: array() as $path) {
    @unlink($path);
}
@rmdir($configDir);
@rmdir(dirname($configDir));
@rmdir(dirname($configDir, 2));
@rmdir($cacheDir);

// px.php's own copy of the address rule: CF-Connecting-IP only from
// Cloudflare's addresses, as Firewall::clientIp() has it.
require_once __DIR__ . '/../src/Firewall.php';
preg_match('/function sa_px_client_ip\(\$trust\)\s*\{.*?\n\}\n/s', (string) file_get_contents($px), $fn);
check('px.php has its address rule', !empty($fn[0]));
if (!empty($fn[0])) {
    eval($fn[0]);
    $_SERVER['HTTP_CF_CONNECTING_IP'] = '198.51.100.7';
    $_SERVER['REMOTE_ADDR'] = '172.68.10.20';
    check('px.php believes the header from Cloudflare', sa_px_client_ip('cloudflare') === '198.51.100.7');
    $_SERVER['REMOTE_ADDR'] = '203.0.113.50';
    check('and from nobody else', sa_px_client_ip('cloudflare') === '203.0.113.50');
    $_SERVER['HTTP_X_FORWARDED_FOR'] = '192.0.2.1, 198.51.100.8:4431';
    check('px.php drops a port on the hop, as the firewall does', sa_px_client_ip('1') === '198.51.100.8');
    $_SERVER['HTTP_X_FORWARDED_FOR'] = 'garbage';
    check('and falls back to the connection for a hop that is no address', sa_px_client_ip('1') === '203.0.113.50');
    unset($_SERVER['HTTP_X_FORWARDED_FOR']);
    unset($_SERVER['HTTP_CF_CONNECTING_IP'], $_SERVER['REMOTE_ADDR']);
}

// The path in the config is the one px.php answers on: if it ever worked one
// out for itself instead, every visit would 404 and nothing would be counted.
check('the configured path is the one served', (new AnalyticsPlatform\Proxy('http://127.0.0.1:1', '', '', $prefix))->scriptUrl() === '/' . $prefix . '/js/v1/s.js');
// The same vector is pinned in the collector, the backend and the other packages.
check('the proxy key is worked out as the collector does',
    AnalyticsPlatform\Proxy::keyFor('0123456789abcdef01234567') === '8fc74dbbd4f088449862841cd29fcaee');
check('the path comes from the secret, not the site id', $prefix === AnalyticsPlatform\Proxy::prefixFor('s3cret')
    && $prefix !== AnalyticsPlatform\Proxy::prefixFor('other'));

echo ($failed ? "FAILED: " : "OK: ") . "$checked checks, $failed failed\n";
exit($failed ? 1 : 0);
