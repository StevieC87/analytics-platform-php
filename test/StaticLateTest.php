<?php
// A static-looking request counted after the response (firewall.md,
// `rate`): compared with the counts first (where they can be read without
// adding: APCu), so an address already over is refused its files, then
// counted toward the rate and the page limits it skipped when it answered
// 400 or more or the router sent it to a page (markRouted(): Laravel's
// route, WordPress's main query). Then the Laravel middleware, with
// stand-ins for its request, route and response.
//
//   php test/StaticLateTest.php

foreach (glob(__DIR__ . '/../src/*.php') as $file) {
    require_once $file;
}
require_once __DIR__ . '/../src/Laravel/FirewallMiddleware.php';

use AnalyticsPlatform\Core;
use AnalyticsPlatform\Firewall;
use AnalyticsPlatform\Laravel\FirewallMiddleware;
use AnalyticsPlatform\Platform;

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
class StaticCore extends Core
{
    public $answer = array();

    public function http($method, $path, $body = null, array $headers = array(), $auth = 'bearer')
    {
        return array('status' => 200, 'body' => json_encode($this->answer), 'headers' => array('etag' => '"1"'));
    }
}

// APCu stands in as an array: the plain PHP these tests run on has none.
class ApcuFirewall extends Firewall
{
    public $local = array();

    protected function countHere($name, $ttl)
    {
        $this->local[$name] = (isset($this->local[$name]) ? $this->local[$name] : 0) + 1;
        return $this->local[$name];
    }

    protected function peekHere($name)
    {
        return isset($this->local[$name]) ? $this->local[$name] : 0;
    }

    protected function noteHere($name, $ttl)
    {
        $this->local['over:' . $name] = 1;
    }

    protected function notedHere($name)
    {
        return isset($this->local['over:' . $name]);
    }
}

$store = sys_get_temp_dir() . '/analytics-static-late-test-' . getmypid();
$options = array('site_id' => 'a1b2c3d4e5f6a1b2c3d4e5f6', 'secret' => 's', 'endpoint' => 'http://127.0.0.1:9', 'storage' => $store);
$search = array('rules' => array(array('id' => 'search', 'action' => 'block', 'limit' => 2, 'window' => 60, 'path' => array('prefix' => array('/search')))));
$answer = array('v' => 1, 'enabled' => true, 'mode' => 'block', 'sync' => 60, 'allow' => array(), 'deny' => array(), 'lists' => array(),
    'shared' => array(), 'goodbots' => array(), 'rate' => null, 'banned' => array(), 'ban' => null, 'limits' => $search);

// A fresh firewall on these rules. $shared: the shared counter's keys, one per hit, or false for none.
function wall(array $more = array(), &$shared = false, $counter = false)
{
    global $options, $answer, $store;
    $rm = function ($dir) use (&$rm) {
        foreach (array_diff(@scandir($dir) ?: array(), array('.', '..')) as $name) {
            is_dir($dir . '/' . $name) ? $rm($dir . '/' . $name) : @unlink($dir . '/' . $name);
        }
        @rmdir($dir);
    };
    $rm($store);
    $core = new StaticCore($options);
    $core->answer = $more + $answer;
    $opts = $options;
    $shared = array();
    if ($counter) {
        $opts['counter'] = function ($key, $ttl) use (&$shared) {
            $shared[] = $key;
            return count(array_keys($shared, $key));
        };
    }
    $wall = new ApcuFirewall($opts, $core);
    $wall->sync(true);
    return $wall;
}

// One request: checked, answered with $status, counted after the response.
function ask(Firewall $wall, $path, $status = 200, $routed = null)
{
    $decision = $wall->check('198.51.100.7', 'GET', $path);
    if ($decision['action'] !== 'block') {
        $wall->countStatic($status, $routed);
    }
    return $decision['action'] === 'block' ? $decision['status'] : $status;
}

// ---- The firewall ----------------------------------------------------------------

$wall = wall();
$got = array();
for ($i = 0; $i < 4; $i++) {
    $got[] = ask($wall, '/search/x.css', 200, true);
}
check('a routed /search/x.css counts toward the /search limit: ' . json_encode($got), $got === array(200, 200, 200, 429));

$wall = wall();
for ($i = 0; $i < 5; $i++) {
    ask($wall, '/search/app.css', 200, false);
    ask($wall, '/search/b.css', 304, true);
    $wall->check('198.51.100.7', 'GET', '/search/c.css');
    $wall->markRouted(true, 'text/css; charset=utf-8');
    $wall->countStatic(200);
}
check('a real file, a 304 and a file a route served are not counted', $wall->local === array());
$pages = array();
for ($i = 0; $i < 3; $i++) {
    $pages[] = $wall->check('198.51.100.7', 'GET', '/search')['rule'];
}
check('the page limit counts from nothing', $pages === array('', '', 'limit:search'));
check('an address over it is refused its files', ask($wall, '/search/app.css') === 429);

$wall = wall(array('rate' => array('limit' => 2, 'window' => 60)));
$got = array();
for ($i = 0; $i < 4; $i++) {
    $got[] = ask($wall, '/made-up.woff2', 404, false);
}
check('an error counts toward the rate with no route: ' . json_encode($got), $got === array(404, 404, 404, 429));

$wall = wall();
$wall->check('198.51.100.7', 'GET', '/search/x.css');
$wall->markRouted(true);
$wall->countStatic(200);
check('markRouted() with no type reads what PHP sends (nothing on the command line): counted', count($wall->local) === 1);
$wall->check('198.51.100.7', 'GET', '/search/y.css');
$wall->countStatic(200);
check('and is forgotten by the next request', count($wall->local) === 1);

// A shared counter only adds: a count this server saw go over is noted (APCu) for the files' peek.
$wall = wall(array(), $shared, true);
check('a static file adds nothing to the shared counter', $wall->check('198.51.100.7', 'GET', '/search/app.css')['rule'] === '' && $shared === array());
$pages = array();
for ($i = 0; $i < 3; $i++) {
    $pages[] = $wall->check('198.51.100.7', 'GET', '/search')['rule'];
}
check('the shared count goes over', $pages === array('', '', 'limit:search'));
check('seen over here: the files are refused without adding', ask($wall, '/search/app.css') === 429 && count($shared) === 3);

// ---- Laravel ----------------------------------------------------------------------

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

class FakeRoute
{
    private $uri;

    public function __construct($uri)
    {
        $this->uri = $uri;
    }

    public function uri()
    {
        return $this->uri;
    }
}

class FakeRequest
{
    public $attributes;
    public $headers;
    public $server;
    private $path;
    public $matched = null;

    public function __construct($path)
    {
        $this->path = $path;
        $this->attributes = new Bag();
        $this->headers = new Bag(array('User-Agent' => 'Mozilla/5.0', 'Accept' => '*/*'));
        $this->server = new Bag(array('REMOTE_ADDR' => '198.51.100.7'));
    }

    public function ip()
    {
        return '198.51.100.7';
    }

    public function method()
    {
        return 'GET';
    }

    public function getMethod()
    {
        return 'GET';
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
        return 'Mozilla/5.0';
    }

    public function route()
    {
        return $this->matched;
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

    public function getStatusCode()
    {
        return $this->status;
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

wall(array(), $shared, true); // writes the rules where the platform reads them
$counted = array();
$platform = new Platform($options + array('platform' => 'laravel', 'inventory' => false, 'resources' => false, 'posture' => false,
    'errors' => false, 'analytics' => false, 'performance' => false, 'crawlers' => false, 'queries' => false, 'queues' => false,
    'counter' => function ($key, $ttl) use (&$counted) {
        $counted[] = $key;
        return count(array_keys($counted, $key));
    }));
$middleware = new FirewallMiddleware($platform);
// One request through the middleware: the app matched $uri (null: none) and answered $type.
$laravel = function ($path, $uri, $type = 'text/html; charset=UTF-8', $status = 200) use ($middleware) {
    $request = new FakeRequest($path);
    $response = $middleware->handle($request, function ($request) use ($uri, $type, $status) {
        $request->matched = $uri === null ? null : new FakeRoute($uri);
        return response('the app', $status, array('Content-Type' => $type));
    });
    $middleware->terminate($request, $response);
    return $response->status;
};
for ($i = 0; $i < 3; $i++) {
    $laravel('/search/a.png', 'search/{id}.png', 'text/html');
    $laravel('/search/b.css', 'storage/{path}', 'text/html');
    $laravel('/search/c.js', 'livewire/livewire.js', 'application/javascript');
    $laravel('/search/d.css', 'search/{q}', 'text/css');
    $laravel('/search/e.css', null, 'text/html');
}
check('file routes, Laravel\'s storage and Livewire routes, a file answered and no route aren\'t counted: ' . json_encode($counted), $counted === array());
$laravel('/search/z.css', null, 'text/html', 404);
check('an unrouted 404 counts in terminate(), by the response\'s status: ' . json_encode($counted), count($counted) === 1);
$laravel('/search/x.css', 'search/{q}');
check('a routed /search/x.css counts toward the /search limit', count($counted) === 2);
check('so the next page is over', $laravel('/search', 'search') === 429);
check('routedToPage', FirewallMiddleware::routedToPage(new FakeRoute('search/{q}')) && !FirewallMiddleware::routedToPage(null)
    && !FirewallMiddleware::routedToPage(new FakeRoute('/avatars/{id}.png')));

$rm = function ($dir) use (&$rm) {
    foreach (array_diff(@scandir($dir) ?: array(), array('.', '..')) as $name) {
        is_dir($dir . '/' . $name) ? $rm($dir . '/' . $name) : @unlink($dir . '/' . $name);
    }
    @rmdir($dir);
};
$rm($store);

echo ($failed ? "FAILED" : "OK") . ": $checked checks, $failed failed\n";
exit($failed ? 1 : 0);
