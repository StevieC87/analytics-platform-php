<?php
// The Symfony integration, without Symfony: it reads every event by its
// methods, so stand-ins for the few interfaces it names are enough. A blocked
// request is answered before the app (or, with protect_only, only on the
// paths and routes named), an exception is sent only when the visitor got a
// 5xx, logged exceptions are sent once, the route is its path
// ("/users/{id}"), read from the route collection once and then from a file,
// and nothing of one request is left for the next (a worker). The collector is a closed port,
// so what would be sent waits in the storage folder, where this reads it.
// Checked in a real Symfony app by hand (README: "Symfony").
//
//   php test/SymfonyTest.php

namespace Symfony\Component\EventDispatcher {
    interface EventSubscriberInterface
    {
        public static function getSubscribedEvents();
    }
}

namespace Symfony\Component\HttpKernel\CacheWarmer {
    interface CacheWarmerInterface
    {
        public function isOptional();
        public function warmUp($cacheDir);
    }
}

namespace Symfony\Contracts\Service {
    interface ResetInterface
    {
        public function reset();
    }
}

namespace Psr\Cache {
    interface CacheItemPoolInterface
    {
    }
}

namespace Symfony\Component\HttpKernel\Exception {
    interface HttpExceptionInterface
    {
        public function getStatusCode();
    }
}

namespace Symfony\Component\Routing {
    interface RouterInterface
    {
    }
}

namespace Symfony\Component\Console\Exception {
    interface ExceptionInterface
    {
    }
}

namespace Symfony\Component\Messenger\Exception {
    class HandlerFailedException extends \RuntimeException
    {
    }
}

namespace Symfony\Component\Security\Http\Authenticator {
    interface InteractiveAuthenticatorInterface
    {
        public function isInteractive();
    }
}

namespace Symfony\Component\HttpFoundation {
    class Response
    {
        public $headers;
        private $content;
        private $status;

        public function __construct($content = '', $status = 200, array $headers = array())
        {
            $this->content = $content;
            $this->status = $status;
            $this->headers = new \Bag($headers);
        }

        public function getStatusCode()
        {
            return $this->status;
        }

        public function getContent()
        {
            return $this->content;
        }
    }
}

namespace {
    foreach (glob(__DIR__ . '/../src/*.php') as $file) {
        require_once $file;
    }
    require_once __DIR__ . '/../src/Symfony/PlatformSubscriber.php';
    require_once __DIR__ . '/../src/Symfony/LogProcessor.php';
    require_once __DIR__ . '/../src/Symfony/CacheCounter.php';

    use AnalyticsPlatform\Challenge;
    use AnalyticsPlatform\Firewall;
    use AnalyticsPlatform\Platform;
    use AnalyticsPlatform\RequestRules;
    use AnalyticsPlatform\Symfony\CacheCounter;
    use AnalyticsPlatform\Symfony\LogProcessor;
    use AnalyticsPlatform\Symfony\PlatformSubscriber;
    use Symfony\Component\HttpFoundation\Response;

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
        public $server;
        public $cookies;
        private $method;
        private $path;

        public function __construct($method, $path, $route = null)
        {
            $this->method = $method;
            $this->path = $path;
            $this->attributes = new Bag($route === null ? array() : array('_route' => $route));
            $this->headers = new Bag(array('User-Agent' => 'Mozilla/5.0'));
            $this->cookies = new Bag();
            // What a worker's terminate sees instead of $_SERVER.
            $this->server = new Bag(array('REQUEST_METHOD' => $method, 'REQUEST_URI' => $path, 'REQUEST_TIME_FLOAT' => microtime(true)));
        }

        public function getClientIp()
        {
            return '203.0.113.7';
        }

        public function getMethod()
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

        public function getQueryString()
        {
            return null;
        }

        public function getContent()
        {
            return '';
        }
    }

    class FakeEvent
    {
        public $response;
        private $request;
        private $throwable;

        public function __construct($request, $response = null, $throwable = null)
        {
            $this->request = $request;
            $this->response = $response;
            $this->throwable = $throwable;
        }

        public function isMainRequest()
        {
            return true;
        }

        public function getRequest()
        {
            return $this->request;
        }

        public function setResponse($response)
        {
            $this->response = $response;
        }

        public function getResponse()
        {
            return $this->response;
        }

        public function getThrowable()
        {
            return $this->throwable;
        }
    }

    class FakeRoute
    {
        private $path;

        public function __construct($path)
        {
            $this->path = $path;
        }

        public function getPath()
        {
            return $this->path;
        }
    }

    class FakeCollection
    {
        private $routes;

        public function __construct(array $routes)
        {
            $this->routes = $routes;
        }

        public function all()
        {
            return array_map(function ($path) {
                return new FakeRoute($path);
            }, $this->routes);
        }
    }

    class FakeRouter implements Symfony\Component\Routing\RouterInterface
    {
        public $routes = array('user_show' => '/users/{id}', 'home' => '/');
        public $loads = 0;
        public $options;

        public function __construct($cacheDir, $debug = false)
        {
            $this->options = array('cache_dir' => $cacheDir, 'debug' => $debug);
        }

        public function getOption($key)
        {
            return $this->options[$key];
        }

        public function getRouteCollection()
        {
            $this->loads++;
            return new FakeCollection($this->routes);
        }
    }

    class NotFound extends \RuntimeException implements Symfony\Component\HttpKernel\Exception\HttpExceptionInterface
    {
        public function getStatusCode()
        {
            return 404;
        }
    }

    class UnknownCommand extends \RuntimeException implements Symfony\Component\Console\Exception\ExceptionInterface
    {
    }

    class FakeAuthenticator implements Symfony\Component\Security\Http\Authenticator\InteractiveAuthenticatorInterface
    {
        public function isInteractive()
        {
            return true;
        }
    }

    class ApiTokenAuthenticator
    {
    }

    class SendReceipt
    {
    }

    $store = sys_get_temp_dir() . '/analytics-symfony-test-' . getmypid();
    $routerCache = $store . '/router';
    @mkdir($routerCache, 0777, true);
    // The errors waiting to be sent, by message.
    $events = function ($dir, $message) {
        $found = array();
        foreach (file($dir . '/errors.retry.jsonl', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: array() as $line) {
            $batch = json_decode($line, true);
            foreach ($batch['body']['errors'] as $event) {
                if ($event['message'] === $message) {
                    $found[] = $event;
                }
            }
        }
        return $found;
    };
    $read = function ($dir, $name) {
        return (string) @file_get_contents($dir . '/' . $name . '.jsonl') . (string) @file_get_contents($dir . '/' . $name . '.retry.jsonl');
    };

    // ---- Route paths ----
    $router = new FakeRouter($routerCache);
    $platform = new Platform(array('site_id' => 'a1b2c3d4e5f6a1b2c3d4e5f6', 'secret' => 'the-site-secret',
        'endpoint' => 'http://127.0.0.1:9', 'storage' => $store . '/platform', 'platform' => 'symfony',
        'inventory' => false, 'resources' => false));
    $subscriber = new PlatformSubscriber($platform, $router);
    check('the matched route is named by its path', $subscriber->routePattern(new FakeRequest('GET', '/users/42', 'user_show')) === '/users/{id}');
    check('no route matched (a 404) is no route', $subscriber->routePattern(new FakeRequest('GET', '/nope')) === '');
    $again = new PlatformSubscriber($platform, $router);
    $again->routePattern(new FakeRequest('GET', '/', 'home'));
    check('the collection is loaded once, then read from the file next to the router\'s cache',
        $router->loads === 1 && is_file($routerCache . '/' . PlatformSubscriber::ROUTES_FILE));
    $again->routePattern(new FakeRequest('GET', '/x', 'gone'));
    (new PlatformSubscriber($platform, $router))->routePattern(new FakeRequest('GET', '/x', 'gone'));
    check('a name the collection lacks is looked for once, not on every request', $router->loads === 2);
    $router->routes['user_show'] = '/people/{id}';
    $debug = new FakeRouter($routerCache, true);
    $debug->routes = $router->routes;
    @touch($routerCache . '/url_matching_routes.php', time() + 5);
    check('in debug mode a newer router cache means the routes changed',
        (new PlatformSubscriber($platform, $debug))->routePattern(new FakeRequest('GET', '/people/1', 'user_show')) === '/people/{id}');
    check('without debug mode the file stands until cache:clear',
        (new PlatformSubscriber($platform, new FakeRouter($routerCache)))->routePattern(new FakeRequest('GET', '/users/1', 'user_show')) === '/people/{id}');
    $router->routes['user_show'] = '/users/{id}';
    $subscriber->warmUp($routerCache);
    check('cache:warmup writes them afresh', (include $routerCache . '/' . PlatformSubscriber::ROUTES_FILE)['user_show'] === '/users/{id}');

    check('an HTTP exception\'s status is its own', PlatformSubscriber::statusOf(new NotFound('no')) === 404);
    check('any other exception is a 500', PlatformSubscriber::statusOf(new \LogicException('bug')) === 500);

    // ---- The firewall, before the app ----
    $dir = $platform->core()->dir();
    $platform->core()->ensureDir();
    $rules = array('v' => Firewall::PROTOCOL, 'etag' => '', 'fetched' => time(), 'enabled' => true, 'mode' => 'block', 'sync' => 300,
        'rate' => null, 'ban' => 0, 'login' => null, 'probes' => Firewall::compileProbes(array('exact' => array('/.env'))),
        'requests' => RequestRules::compile(null));
    foreach (Firewall::RULES as $list) {
        $rules[$list] = array();
    }
    $platform->core()->writePhp('rules.php', $rules);
    $subscriber = new PlatformSubscriber(new Platform(array('site_id' => 'a1b2c3d4e5f6a1b2c3d4e5f6', 'secret' => 'the-site-secret',
        'endpoint' => 'http://127.0.0.1:9', 'storage' => $store . '/platform', 'platform' => 'symfony',
        'inventory' => false, 'resources' => false)), $router);
    $probe = new FakeEvent(new FakeRequest('GET', '/.env'));
    $subscriber->onRequest($probe);
    check('a probe is answered 403 before the app runs', $probe->response instanceof Response && $probe->response->getStatusCode() === 403
        && $probe->response->getContent() === 'Forbidden');
    check('and reported', strpos($read($dir, 'events'), '"rule":"probe"') !== false);
    $page = new FakeEvent(new FakeRequest('GET', '/users/1', 'user_show'));
    $subscriber->onRequest($page);
    check('a page goes on to the app', $page->response === null);

    // ---- The browser check ----
    $rules['challenge'] = Challenge::compile(array('skip' => array('/api/'), 'exempt' => array()));
    $platform->core()->writePhp('rules.php', $rules);
    $checking = new PlatformSubscriber(new Platform(array('site_id' => 'a1b2c3d4e5f6a1b2c3d4e5f6', 'secret' => 'the-site-secret',
        'endpoint' => 'http://127.0.0.1:9', 'storage' => $store . '/platform', 'platform' => 'symfony',
        'inventory' => false, 'resources' => false)), $router);
    $browser = function ($method, $path, $accept, $pass = null) use ($checking) {
        $request = new FakeRequest($method, $path);
        $request->headers->set('Accept', $accept);
        if ($pass !== null) {
            // The raw header, as a browser sends it: a stale pass first, then this one.
            $request->headers->set('Cookie', Challenge::COOKIE . '=20000.' . str_repeat('0', 32) . '; ' . Challenge::COOKIE . '=' . $pass);
        }
        $event = new FakeEvent($request);
        $checking->onRequest($event);
        return $event->response;
    };
    $html = 'text/html,application/xhtml+xml,*/*;q=0.8';
    $checkPage = $browser('GET', '/pricing', $html);
    check('a page load without a pass gets the check page before the app', $checkPage instanceof Response
        && $checkPage->getStatusCode() === 503 && $checkPage->headers->get('Cache-Control') === 'no-store'
        && strpos((string) $checkPage->headers->get('Content-Security-Policy'), "script-src 'nonce-") !== false
        && strpos($checkPage->getContent(), Challenge::token('the-site-secret', '203.0.113.7')) !== false);
    check('and is reported as rule challenge, action block', strpos($read($dir, 'events'), '"rule":"challenge","action":"block"') !== false);
    check('a HEAD gets it without the body', ($head = $browser('HEAD', '/pricing', $html)) && $head->getStatusCode() === 503 && $head->getContent() === '');
    check('with the pass the page goes on to the app', $browser('GET', '/pricing', $html, Challenge::token('the-site-secret', '203.0.113.7')) === null);
    check('a POST goes on to the app', $browser('POST', '/pricing', $html) === null);
    check('a JSON call goes on to the app', $browser('GET', '/pricing', 'application/json') === null);
    check('a skipped path goes on to the app', $browser('GET', '/api/orders', $html) === null);
    unset($rules['challenge']);
    $platform->core()->writePhp('rules.php', $rules);

    // ---- Errors and timing, after the response ----
    $request = new FakeRequest('GET', '/users/42', 'user_show');
    $subscriber->onException(new FakeEvent($request, null, new \RuntimeException('database down')));
    $subscriber->onTerminate(new FakeEvent($request, new Response('', 500)));
    $notFound = new FakeRequest('GET', '/users/43', 'user_show');
    $subscriber->onException(new FakeEvent($notFound, null, new NotFound('no such user')));
    $subscriber->onTerminate(new FakeEvent($notFound, new Response('', 404)));
    // framework.exceptions or #[WithHttpStatus] made this one a 422.
    $mapped = new FakeRequest('POST', '/users/44', 'user_show');
    $subscriber->onException(new FakeEvent($mapped, null, new \DomainException('out of stock')));
    $subscriber->onTerminate(new FakeEvent($mapped, new Response('', 422)));
    $sent = $read($dir, 'errors');
    check('a 500 is sent with the route\'s path and its status', strpos($sent, '"message":"database down"') !== false
        && strpos($sent, '"route":"\/users\/{id}"') !== false && strpos($sent, '"path":"\/users\/42"') !== false
        && strpos($sent, '"status_code":500') !== false);
    check('a 404 is not sent', strpos($sent, 'no such user') === false);
    check('nor an exception whose response is a 4xx', strpos($sent, 'out of stock') === false);
    $timed = $read($dir, 'requests');
    check('each request is timed under the route\'s path, with its status', strpos($timed, '"\/users\/{id}"') !== false
        && (strpos($timed, '"s":404') !== false || strpos($timed, '"status":404') !== false));

    // ---- Messenger, the console, logins ----
    $envelope = new class {
        public function getMessage()
        {
            return new SendReceipt();
        }
    };
    $job = new class($envelope) {
        private $envelope;

        public function __construct($envelope)
        {
            $this->envelope = $envelope;
        }

        public function getEnvelope()
        {
            return $this->envelope;
        }

        public function getThrowable()
        {
            return new Symfony\Component\Messenger\Exception\HandlerFailedException('Handling "SendReceipt" failed: card declined', 0, new \RuntimeException('card declined'));
        }
    };
    $subscriber->onMessageReceived($job);
    $subscriber->onMessageFailed($job);
    $sent = $read($dir, 'errors');
    check('a failed message is sent as a job named after its class, with the handler\'s own exception',
        strpos($sent, '"route":"\/(job) SendReceipt"') !== false && strpos($sent, '"message":"card declined"') !== false);

    $command = function ($error, $name) {
        return new class($error, $name) {
            private $error;
            private $name;

            public function __construct($error, $name)
            {
                $this->error = $error;
                $this->name = $name;
            }

            public function getError()
            {
                return $this->error;
            }

            public function getCommand()
            {
                $name = $this->name;
                return new class($name) {
                    private $name;

                    public function __construct($name)
                    {
                        $this->name = $name;
                    }

                    public function getName()
                    {
                        return $this->name;
                    }
                };
            }
        };
    };
    $subscriber->onConsoleError($command(new UnknownCommand('Command "imprt" is not defined.'), 'imprt'));
    $subscriber->onConsoleError($command(new \RuntimeException('import failed'), 'app:import'));
    $subscriber->onConsoleTerminate(null);
    $sent = $read($dir, 'errors');
    check('a command that fails is sent, named as a job', strpos($sent, '"route":"\/(job) app:import"') !== false);
    check('a mistyped command is not', strpos($sent, 'imprt') === false);

    $login = function ($authenticator) {
        return new class($authenticator) {
            private $authenticator;

            public function __construct($authenticator)
            {
                $this->authenticator = $authenticator;
            }

            public function getAuthenticator()
            {
                return $this->authenticator;
            }

            public function getRequest()
            {
                return new FakeRequest('POST', '/login');
            }
        };
    };
    @unlink($dir . '/events.jsonl');
    $subscriber->onLoginFailure($login(new ApiTokenAuthenticator()));
    check('a refused API token is not a failed login', strpos($read($dir, 'events'), '"rule":"login"') === false);
    $subscriber->onLoginFailure($login(new FakeAuthenticator()));
    check('a refused password is', strpos($read($dir, 'events'), '"rule":"login","action":"monitor"') !== false);

    // ---- A worker: nothing of one request is left for the next ----
    $_SERVER['REQUEST_URI'] = '/the-worker-started-here';
    $_SERVER['REQUEST_TIME_FLOAT'] = microtime(true) - 3600;
    $first = new FakeRequest('GET', '/users/7', 'user_show');
    $subscriber->onRouted(new FakeEvent($first));
    $platform2 = new ReflectionProperty($subscriber, 'platform');
    $platform2->setAccessible(true);
    $platform2->getValue($subscriber)->addBreadcrumb('a step of the first request');
    $subscriber->onException(new FakeEvent($first, null, new \RuntimeException('first request failed')));
    $subscriber->onTerminate(new FakeEvent($first, new Response('', 500)));
    $subscriber->reset();
    $second = new FakeRequest('GET', '/elsewhere');
    $subscriber->onTerminate(new FakeEvent($second, new Response('', 200)));
    $platform2->getValue($subscriber)->captureException(new \RuntimeException('captured by hand'));
    $platform2->getValue($subscriber)->sendErrors();
    $sent = $read($dir, 'errors');
    $timed = $read($dir, 'requests');
    check('in a worker each request is timed as itself, not from $_SERVER', strpos($timed, '"r":"\/elsewhere","s":200') !== false
        && strpos($timed, 'the-worker-started-here') === false && strpos($timed, '"d":36') === false);
    $byHand = $events($dir, 'captured by hand');
    check('the next request keeps neither the last one\'s route nor its steps', count($byHand) === 1
        && $byHand[0]['route'] !== '/users/{id}' && !isset($byHand[0]['breadcrumbs']));
    check('and its exception is not sent again', count($events($dir, 'first request failed')) === 1);

    // ---- protect_only ----
    // Every request from the test's address is turned away, where the firewall looks.
    $rules['deny'] = Firewall::compileList(array('203.0.113.7'));
    $platform->core()->writePhp('rules.php', $rules);
    $only = array('/admin', 'checkout_*', 'login');
    check('a path covers itself and below it', PlatformSubscriber::pathListed($only, '/admin') && PlatformSubscriber::pathListed($only, '/admin/users/1'));
    check('and nothing that only starts the same', !PlatformSubscriber::pathListed($only, '/administrator') && !PlatformSubscriber::pathListed($only, '/users'));
    check('a route by name, or by the start of its name', PlatformSubscriber::routeListed($only, 'login') && PlatformSubscriber::routeListed($only, 'checkout_pay')
        && !PlatformSubscriber::routeListed($only, 'login_check') && !PlatformSubscriber::routeListed($only, ''));
    $scoped = new PlatformSubscriber(new Platform(array('site_id' => 'a1b2c3d4e5f6a1b2c3d4e5f6', 'secret' => 'the-site-secret',
        'endpoint' => 'http://127.0.0.1:9', 'storage' => $store . '/platform', 'platform' => 'symfony',
        'inventory' => false, 'resources' => false, 'protect_only' => array('/admin', 'checkout_*'))), $router);
    $outside = new FakeEvent(new FakeRequest('GET', '/.env'));
    $scoped->onRequest($outside);
    $inside = new FakeEvent(new FakeRequest('GET', '/admin/users'));
    $scoped->onRequest($inside);
    $named = new FakeEvent(new FakeRequest('GET', '/shop/pay', 'checkout_pay'));
    $scoped->onRequest($named);
    check('outside them the firewall leaves the request alone', $outside->response === null);
    check('below a listed path it checks before routing', $inside->response && $inside->response->getStatusCode() === 403);
    $scoped->onRouted($named);
    check('a listed route is checked once routed', $named->response && $named->response->getStatusCode() === 403);

    // ---- Logged exceptions ----
    $logged = new LogProcessor($platform);
    $record = function ($level, $error, $channel = 'app') {
        return array('message' => 'x', 'level' => $level, 'channel' => $channel, 'context' => array('exception' => $error), 'extra' => array());
    };
    $rethrown = new \RuntimeException('logged then thrown');
    $same = $logged($record(400, new \RuntimeException('logged at error')));
    $logged($record(300, new \RuntimeException('only a warning')));
    $logged($record(500, new NotFound('Symfony reports its own 404'), 'request'));
    $logged($record(500, $rethrown));
    $platform->captureException($rethrown, null, 500, 'error');
    $platform->sendErrors();
    $sent = $read($dir, 'errors');
    check('the record is handed back unchanged', $same['message'] === 'x' && $same['level'] === 400);
    check('an exception logged at error is sent as logged', strpos($sent, '"message":"logged at error","error_type":"RuntimeException","stack"') !== false
        && preg_match('/"message":"logged at error".*?"kind":"logged"/', $sent) === 1);
    check('a warning is not, nor Symfony\'s own report of an exception', strpos($sent, 'only a warning') === false && strpos($sent, 'its own 404') === false);
    $once = $events($dir, 'logged then thrown');
    check('logged and then thrown is sent once, as the error it became', count($once) === 1
        && $once[0]['kind'] === 'error' && $once[0]['status_code'] === 500);

    // ---- Rate limit counter ----
    $pool = new class implements Psr\Cache\CacheItemPoolInterface {
        public $items = array();

        public function getItem($key)
        {
            $pool = $this;
            return isset($this->items[$key]) ? $this->items[$key] : new class($key) {
                public $key;
                public $value = null;
                public $hit = false;

                public function __construct($key)
                {
                    $this->key = $key;
                }

                public function isHit()
                {
                    return $this->hit;
                }

                public function get()
                {
                    return $this->value;
                }

                public function set($value)
                {
                    $this->value = $value;
                    return $this;
                }

                public function expiresAfter($ttl)
                {
                    return $this;
                }
            };
        }

        public function save($item)
        {
            $item->hit = true;
            $this->items[$item->key] = $item;
            return true;
        }
    };
    $counter = new CacheCounter($pool);
    $counter('afw:site:key:1', 120);
    $counter('afw:site:key:1', 120);
    check('without APCu the app\'s cache counts', function_exists('apcu_enabled') && apcu_enabled() ? true : $counter('afw:site:key:1', 120) === 3);
    check('under a key a cache pool accepts', function_exists('apcu_enabled') && apcu_enabled() ? true : isset($pool->items['analytics_platform.afw.site.key.1']));
    check('with no cache at all it counts nothing (no rate limit)', function_exists('apcu_enabled') && apcu_enabled() ? true : (new CacheCounter())('k', 60) === 0);

    foreach (array($dir, $routerCache) as $folder) {
        foreach (glob($folder . '/{,.}*', GLOB_BRACE) ?: array() as $path) {
            if (is_file($path)) {
                @unlink($path);
            }
        }
        @rmdir($folder);
    }
    @rmdir($store . '/platform');
    @rmdir($store);

    echo ($failed ? "FAILED" : "OK") . ": $checked checks, $failed failed\n";
    exit($failed ? 1 : 0);
}
