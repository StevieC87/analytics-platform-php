<?php
// The browser check (sdk/protocols/firewall.md, "Flood protection" →
// "challenge"), against the cases every client shares:
// sdk/protocols/challenge-cases.json (tokens, valid and invalid passes, which
// requests are checked). Then the firewall around it: a checked page gets the
// check page and is reported, a POST or an API call passes, and rules without
// `challenge` change nothing.
//
//   php test/ChallengeTest.php
// (No dependencies: the package has none, so this is plain PHP, not PHPUnit.)

require __DIR__ . '/../src/Core.php';
require __DIR__ . '/../src/RequestRules.php';
require __DIR__ . '/../src/Challenge.php';
require __DIR__ . '/../src/Firewall.php';

use AnalyticsPlatform\Challenge;
use AnalyticsPlatform\Core;
use AnalyticsPlatform\Firewall;

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

// ---- The shared cases ----
// Deliberately not copied in here: a copy would drift, which is what the
// shared file exists to prevent.
$casesFile = __DIR__ . '/../../protocols/challenge-cases.json';
if (!is_file($casesFile)) {
    echo "SKIP: the shared protocol fixtures are not alongside this package\n";
} else {
    $cases = json_decode((string) file_get_contents($casesFile), true);
    if (!is_array($cases) || empty($cases['tokens']) || empty($cases['checks']) || empty($cases['decisions'])) {
        fwrite(STDERR, "Could not read the shared cases.\n");
        exit(1);
    }
    $secret = $cases['secret'];
    foreach ($cases['tokens'] as $case) {
        check("who({$case['ip']}) is {$case['who']}", Challenge::who($case['ip']) === $case['who']);
        check("the pass for {$case['ip']}", Challenge::token($secret, $case['ip'], $case['now']) === $case['token']);
    }
    foreach ($cases['checks'] as $case) {
        check("pass check: {$case['why']}", Challenge::valid($secret, $case['ip'], $case['cookie'], $case['now']) === $case['valid']);
    }
    $challenge = Challenge::compile($cases['challenge']);
    foreach ($cases['decisions'] as $case) {
        $r = $case['request'];
        check("decision: {$case['why']}", Challenge::needed($challenge, $secret, $r['ip'], $r['method'], $r['path'],
            $r['accept'], $r['cookie'], $case['now']) === $case['challenged']);
    }
}

// ---- The pass, beyond the shared cases ----
check('not an address: no pass', Challenge::who('nonsense') === null && Challenge::token('s', 'nonsense') === null);
check('an IPv4-mapped address in hex is IPv4 too', Challenge::who('::ffff:cb00:7107') === '203.0.113.7');
check('a pass for a non-address is never valid', !Challenge::valid('s', 'nonsense', '20761.0ddc48fd8c38f7a225623a9a27f1d364'));
check('a pass with a leading zero on its day is not the same pass',
    !Challenge::valid('s', '203.0.113.7', '0' . Challenge::token('s', '203.0.113.7')));
check('nor one with anything after it', !Challenge::valid('s', '203.0.113.7', Challenge::token('s', '203.0.113.7') . "\n"));
check('another site\'s pass is not this one\'s', !Challenge::valid('other', '203.0.113.7', Challenge::token('s', '203.0.113.7')));
check('the pass is found in a Cookie header', Challenge::fromCookieHeader('a=1; __sg_pass=20761.abc; b=2') === '20761.abc');
check('the first one wins', Challenge::fromCookieHeader('__sg_pass=one;__sg_pass=two') === 'one');
check('every pass, quoted or not, up to four', Challenge::cookieValues('a=1; __sg_pass=x; __sg_pass="y"; b=2') === array('x', 'y')
    && count(Challenge::cookieValues(str_repeat('__sg_pass=z; ', 6))) === 4 && Challenge::cookieValues('__sg_passn=z') === array());
$good = Challenge::token('s', '198.51.100.9');
check('a stale pass before the good one still lets the browser in', Challenge::anyValid('s', '198.51.100.9', array('20000.' . str_repeat('0', 32), $good))
    && !Challenge::anyValid('s', '198.51.100.9', array('20000.' . str_repeat('0', 32))) && Challenge::anyValid('s', '198.51.100.9', $good));
check('not a cookie that only ends the same', Challenge::fromCookieHeader('x__sg_pass=1; __sg_passn=2') === '');
check('no rules: nothing is checked', !Challenge::needed(null, 's', '198.51.100.9', 'GET', '/', 'text/html', ''));

// ---- The page ----
$ip = '198.51.100.9';
$page = Challenge::page('s', $ip, 'GET');
check('the page is a 503', $page['status'] === 503);
check('with its headers', $page['headers']['Content-Type'] === 'text/html; charset=utf-8'
    && $page['headers']['Cache-Control'] === 'no-store' && $page['headers']['X-Robots-Tag'] === 'noindex');
preg_match("/script-src 'nonce-([0-9a-f]+)'/", $page['headers']['Content-Security-Policy'], $nonce);
check('its own policy allows its script by nonce', !empty($nonce[1])
    && strpos($page['body'], '<script nonce="' . $nonce[1] . '">') !== false
    && strpos($page['headers']['Content-Security-Policy'], "default-src 'none'") === 0);
$again = Challenge::page('s', $ip, 'GET');
check('a fresh nonce every time', $again['headers']['Content-Security-Policy'] !== $page['headers']['Content-Security-Policy']);
check('the script sets this address\'s pass', strpos($page['body'], '"__sg_pass=' . Challenge::token('s', $ip) . '"') !== false);
check('for a day, on the whole site, Lax', strpos($page['body'], 'Max-Age=86400; Path=/; SameSite=Lax') !== false);
check('Secure on https', strpos($page['body'], 's=location.protocol==="https:"') !== false && strpos($page['body'], '(s?"; Secure":"")') !== false);
check('reloads only when the cookie reads back', preg_match('/indexOf\("; "\+c\+";"\)<0\)\{m\.textContent=[^}]*cookies[^}]*;return;\}.*location\.reload\(\);/', $page['body']) === 1);
check('stops after three tries within 60 seconds', strpos($page['body'], 'return t-x<60000;') !== false
    && strpos($page['body'], 'if(r>=3){m.textContent=') !== false && strpos($page['body'], 'address keeps changing') !== false);
check('counts in a cookie where sessionStorage throws', strpos($page['body'], 'catch(e){l=/(?:^|; )__sg_tries=([0-9]+)/.exec(document.cookie)') !== false
    && strpos($page['body'], 'document.cookie=k+"="+(r+1)+"; Max-Age=60; Path=/; SameSite=Lax"') !== false);
check('its own frame-ancestors', strpos(Challenge::page('s', $ip)['headers']['Content-Security-Policy'], "frame-ancestors 'none'") !== false);
check('asks for JavaScript without it', strpos($page['body'], '<noscript>') !== false);
$head = Challenge::page('s', $ip, 'HEAD');
check('a HEAD gets the status and headers without the body', $head['status'] === 503 && $head['body'] === ''
    && $head['headers']['Cache-Control'] === 'no-store' && isset($head['headers']['Content-Security-Policy']));

// ---- The firewall around it ----

// Answers the rules fetch with $answer and keeps the headers it was sent.
class RulesCore extends Core
{
    public $answer = array();
    public $sent = array();

    public function http($method, $path, $body = null, array $headers = array(), $auth = 'bearer')
    {
        $this->sent = $headers;
        return array('status' => 200, 'body' => json_encode($this->answer), 'headers' => array('etag' => '"1"'));
    }
}

$store = sys_get_temp_dir() . '/analytics-challenge-test-' . getmypid();
$options = array('site_id' => 'a1b2c3d4e5f6a1b2c3d4e5f6', 'secret' => 'the-site-secret', 'endpoint' => 'http://127.0.0.1:9',
    'storage' => $store, 'server_name' => str_repeat('n', 150));
$base = array('v' => 1, 'enabled' => true, 'mode' => 'monitor', 'sync' => 60, 'allow' => array('192.0.2.1'), 'deny' => array(),
    'lists' => array(), 'shared' => array(), 'rate' => null, 'goodbots' => array('192.0.2.50/31'));
$html = 'text/html,application/xhtml+xml,*/*;q=0.8';
$events = function (Core $core) {
    $file = $core->dir() . '/events.jsonl';
    $rows = is_file($file) ? array_map(function ($line) {
        return json_decode($line, true);
    }, file($file, FILE_IGNORE_NEW_LINES)) : array();
    @unlink($file);
    return $rows;
};
$firewall = function (array $answer) use ($options) {
    $core = new RulesCore($options);
    $core->answer = $answer;
    $wall = new Firewall($options, $core);
    $wall->sync(true);
    return array($wall, $core);
};

list($wall, $core) = $firewall($base + array('challenge' => array('skip' => array('/api/'), 'exempt' => array('66.249.64.0/27'))));
check('the rules fetch names this server\'s layers', in_array('X-Firewall-Layers: app check', $core->sent, true));
check('and the server, 100 characters at most', in_array('X-Server-Name: ' . str_repeat('n', 100), $core->sent, true));
check('the status says the check is on', $wall->status()['challenge'] === true);
$events($core);

$decision = $wall->check($ip, 'GET', '/pricing?x=1', 'curl-ish', $html, '');
check('a page load without a pass is checked', $decision === array('action' => 'block', 'rule' => 'challenge', 'status' => 503));
$reported = $events($core);
check('and reported as rule challenge, action block, path without its query', count($reported) === 1
    && $reported[0]['rule'] === 'challenge' && $reported[0]['action'] === 'block' && $reported[0]['path'] === '/pricing'
    && $reported[0]['ip'] === $ip && $reported[0]['method'] === 'GET');
check('even in monitor mode: not a mode matter', $decision['action'] === 'block');
$page = $wall->challengePage($ip, 'GET');
check('its page carries the pass, signed with the site secret', strpos($page['body'], Challenge::token('the-site-secret', $ip)) !== false);
check('with a valid pass it passes', $wall->check($ip, 'GET', '/pricing', '', $html, Challenge::token('the-site-secret', $ip))['action'] === 'allow');
check('a POST passes', $wall->check($ip, 'POST', '/pricing', '', $html, '')['action'] === 'allow');
check('an API call passes', $wall->check($ip, 'GET', '/pricing', '', 'application/json', '')['action'] === 'allow');
check('a skipped path passes', $wall->check($ip, 'GET', '/API/orders', '', $html, '')['action'] === 'allow');
check('an exempt address passes', $wall->check('66.249.64.5', 'GET', '/pricing', '', $html, '')['action'] === 'allow');
check('an allowed address passes', $wall->check('192.0.2.1', 'GET', '/pricing', '', $html, '')['action'] === 'allow');
check('a good bot passes', $wall->check('192.0.2.51', 'GET', '/pricing', '', $html, '')['action'] === 'allow');
check('a caller that passes no Accept checks nothing', $wall->check($ip, 'GET', '/pricing', '')['action'] === 'allow');
check('nothing that passed was reported', $events($core) === array());
$denied = $firewall(array_merge($base, array('mode' => 'block', 'deny' => array($ip), 'challenge' => array('skip' => array(), 'exempt' => array()))))[0];
check('an earlier rule still wins', $denied->check($ip, 'GET', '/pricing', '', $html, '')['rule'] === 'deny');
$events($core);
list($watched, $watchedCore) = $firewall(array_merge($base, array('deny' => array($ip), 'challenge' => array('skip' => array(), 'exempt' => array()))));
$events($watchedCore);
check('a match only watched (monitor) still gets the check', $watched->check($ip, 'GET', '/pricing', '', $html, '')
    === array('action' => 'block', 'rule' => 'challenge', 'status' => 503));
$rows = $events($watchedCore);
check('and both are reported', count($rows) === 2 && $rows[0]['rule'] === 'deny' && $rows[0]['action'] === 'monitor'
    && $rows[1]['rule'] === 'challenge');
check('a POST from it is only watched, as before', $watched->check($ip, 'POST', '/pricing', '', $html, '')['action'] === 'monitor');
$events($watchedCore);

list($off, $offCore) = $firewall($base + array('challenge' => null));
check('challenge null: a page load passes', $off->check($ip, 'GET', '/pricing', '', $html, '')['action'] === 'allow');
check('and the status says it is off', $off->status()['challenge'] === false);
list($absent) = $firewall($base);
check('no challenge key: the same', $absent->check($ip, 'GET', '/pricing', '', $html, '')['action'] === 'allow');
list($disabled) = $firewall(array_merge($base, array('enabled' => false, 'challenge' => array('skip' => array(), 'exempt' => array()))));
check('the firewall off: nothing is checked', $disabled->check($ip, 'GET', '/pricing', '', $html, '')['action'] === 'allow');
check('nothing was reported', $events($offCore) === array());

// Clean up.
$rm = function ($dir) use (&$rm) {
    foreach (array_diff(scandir($dir) ?: array(), array('.', '..')) as $name) {
        is_dir($dir . '/' . $name) ? $rm($dir . '/' . $name) : @unlink($dir . '/' . $name);
    }
    @rmdir($dir);
};
$rm($store);

echo ($failed ? "FAILED" : "OK") . ": $checked checks, $failed failed\n";
exit($failed ? 1 : 0);
