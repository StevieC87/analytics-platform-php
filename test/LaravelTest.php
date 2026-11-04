<?php
// The Laravel middleware's firewall, without Laravel: stand-ins for the
// request and the response() helper are all it calls. A page load without a
// pass gets the browser check's page (the pass read from the Cookie header
// itself, which EncryptCookies leaves alone), and everything else goes on to
// the app.
//
//   php test/LaravelTest.php

foreach (glob(__DIR__ . '/../src/*.php') as $file) {
    require_once $file;
}
require_once __DIR__ . '/../src/Laravel/FirewallMiddleware.php';

use AnalyticsPlatform\Challenge;
use AnalyticsPlatform\Firewall;
use AnalyticsPlatform\Laravel\FirewallMiddleware;
use AnalyticsPlatform\Platform;
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

class Bag
{
    private $values;

    public function __construct(array $values = array())
    {
        $this->values = $values;
    }

    public function get($key, $default = null)
    {
        return array_key_exists($key, $this->values) ? $this->values[$key] : $default;
    }

    public function set($key, $value)
    {
        $this->values[$key] = $value;
    }

    public function has($key)
    {
        return array_key_exists($key, $this->values);
    }

    public function all()
    {
        return $this->values;
    }
}

class FakeRequest
{
    public $attributes;
    public $headers;
    public $cookies;
    private $method;
    private $path;

    public function __construct($method, $path, array $headers)
    {
        $this->method = $method;
        $this->path = $path;
        $this->attributes = new Bag();
        $this->headers = new Bag($headers + array('User-Agent' => 'Mozilla/5.0'));
        // What EncryptCookies leaves in the bag for a cookie it didn't encrypt.
        $this->cookies = new Bag(array(Challenge::COOKIE => null));
    }

    public function ip()
    {
        return '203.0.113.7';
    }

    public function method()
    {
        return $this->method;
    }

    public function getPathInfo()
    {
        return $this->path;
    }

    public function getRequestUri()
    {
        return $this->path;
    }

    public function userAgent()
    {
        return $this->headers->get('User-Agent');
    }
}

class FakeResponse
{
    public $headers;
    public $content;
    public $status;

    public function __construct($content, $status, array $headers)
    {
        $this->content = $content;
        $this->status = $status;
        $this->headers = new Bag($headers);
    }

    public function header($name, $value)
    {
        $this->headers->set($name, $value);
        return $this;
    }
}

function response($content = '', $status = 200, array $headers = array())
{
    return new FakeResponse($content, $status, $headers);
}

$store = sys_get_temp_dir() . '/analytics-laravel-test-' . getmypid();
$platform = new Platform(array('site_id' => 'a1b2c3d4e5f6a1b2c3d4e5f6', 'secret' => 'the-site-secret',
    'endpoint' => 'http://127.0.0.1:9', 'storage' => $store, 'platform' => 'laravel', 'inventory' => false, 'resources' => false));
$platform->core()->ensureDir();
$rules = array('v' => Firewall::PROTOCOL, 'etag' => '', 'fetched' => time(), 'enabled' => true, 'mode' => 'monitor', 'sync' => 300,
    'rate' => null, 'ban' => 0, 'login' => null, 'probes' => null, 'requests' => RequestRules::compile(null),
    'challenge' => Challenge::compile(array('skip' => array('/api/'), 'exempt' => array())));
foreach (Firewall::RULES as $list) {
    $rules[$list] = array();
}
$platform->core()->writePhp('rules.php', $rules);
$middleware = new FirewallMiddleware($platform);
$app = function () {
    return new FakeResponse('the app', 200, array());
};
$html = 'text/html,application/xhtml+xml,*/*;q=0.8';
$pass = Challenge::token('the-site-secret', '203.0.113.7');

$page = $middleware->handle(new FakeRequest('GET', '/pricing', array('Accept' => $html)), $app);
check('a page load without a pass gets the check page', $page->status === 503 && $page->content !== 'the app'
    && strpos($page->content, $pass) !== false && $page->headers->get('X-Robots-Tag') === 'noindex'
    && strpos((string) $page->headers->get('Content-Security-Policy'), "script-src 'nonce-") !== false);
$events = (string) @file_get_contents($platform->core()->dir() . '/events.jsonl');
check('and is reported as rule challenge, action block', strpos($events, '"rule":"challenge","action":"block"') !== false);
check('the pass is read from the Cookie header, past EncryptCookies',
    $middleware->handle(new FakeRequest('GET', '/pricing', array('Accept' => $html, 'Cookie' => 'x=1; ' . Challenge::COOKIE . '=' . $pass)), $app)->content === 'the app');
check('a POST goes on to the app', $middleware->handle(new FakeRequest('POST', '/pricing', array('Accept' => $html)), $app)->content === 'the app');
check('a JSON call goes on to the app', $middleware->handle(new FakeRequest('GET', '/pricing', array('Accept' => 'application/json')), $app)->content === 'the app');
check('a skipped path goes on to the app', $middleware->handle(new FakeRequest('GET', '/api/x', array('Accept' => $html)), $app)->content === 'the app');
unset($rules['challenge']);
$platform->core()->writePhp('rules.php', $rules);
$fresh = new FirewallMiddleware(new Platform(array('site_id' => 'a1b2c3d4e5f6a1b2c3d4e5f6', 'secret' => 'the-site-secret',
    'endpoint' => 'http://127.0.0.1:9', 'storage' => $store, 'platform' => 'laravel', 'inventory' => false, 'resources' => false)));
check('without challenge in the rules a page load goes on to the app',
    $fresh->handle(new FakeRequest('GET', '/pricing', array('Accept' => $html)), $app)->content === 'the app');

$rm = function ($dir) use (&$rm) {
    foreach (array_diff(scandir($dir) ?: array(), array('.', '..')) as $name) {
        is_dir($dir . '/' . $name) ? $rm($dir . '/' . $name) : @unlink($dir . '/' . $name);
    }
    @rmdir($dir);
};
$rm($store);

echo ($failed ? "FAILED" : "OK") . ": $checked checks, $failed failed\n";
exit($failed ? 1 : 0);
