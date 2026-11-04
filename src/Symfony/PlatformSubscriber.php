<?php
// Symfony 6.4 and later: one event subscriber does what Laravel's middleware
// and service provider do. Registered in config/services.yaml next to the
// Platform it is given (README: "Symfony"); autoconfigure tags it.
//
// - kernel.request, before every other listener: the proxy's two addresses,
//   then the firewall, then maintenance mode. A blocked request is answered
//   there, so no controller, session or security listener runs for it. With
//   the 'protect_only' option, the firewall and maintenance mode cover only
//   the paths and routes it names (Laravel: the middleware on some routes).
// - kernel.response: the security headers the response doesn't set itself.
// - kernel.exception and kernel.terminate: an exception is sent once the
//   response is out, when the visitor got a 5xx (so a 404 or an access denied
//   isn't), and the request is timed under its route's path ("/users/{id}").
// - Messenger workers (messenger:consume): each message is a job, timed and
//   its errors sent with the message's class as their route, as Laravel's
//   queue jobs are. What is captured between messages is sent on the
//   worker's next turn. A command that fails (console.error) is sent too.
// - Security: failed form and JSON logins count for bot protection; logins
//   and logouts go to the audit log.
//
// The visitor's address is $request->getClientIp(), so Symfony's
// trusted_proxies decide it. Everything is read from the Request, not from
// $_SERVER, so a worker that serves many requests from one process
// (FrankenPHP, RoadRunner) is named and timed per request; kernel.reset
// forgets each one, and kernel.request starts each one's database queries
// afresh (QueryMiddleware times them). Nothing here needs a Symfony class to load except the
// interfaces it implements: every event is read by its methods.

namespace AnalyticsPlatform\Symfony;

use AnalyticsPlatform\Challenge;
use AnalyticsPlatform\Platform;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\CacheWarmer\CacheWarmerInterface;
use Symfony\Contracts\Service\ResetInterface;

class PlatformSubscriber implements EventSubscriberInterface, CacheWarmerInterface, ResetInterface
{
    // Marks a request answered by the proxy, so the rest leaves it alone.
    const PROXIED = 'analytics-platform.proxied';
    // Marks a request the firewall has checked.
    const CHECKED = 'analytics-platform.checked';
    // The route's path, on the request, for the errors logged during it (LogProcessor).
    const ROUTE = 'analytics-platform.route';
    // The check page's own headers, put back last: a CSP listener (Nelmio,
    // the app's own) would otherwise replace the nonce policy and block the
    // page's script, so no visitor could ever get past it.
    const CHECK_PAGE = 'analytics-platform.check-page';
    // When the request reached Symfony, for a server that doesn't say (Swoole).
    const STARTED = 'analytics-platform.started';
    // Route name => path, next to the router's own cache.
    const ROUTES_FILE = 'analytics_platform_routes.php';

    private $platform;
    private $router;
    private $paths = null;
    // The main request's exception, sent at terminate when the response is a 5xx.
    private $exception = null;
    private $request = null;
    private $shutdown = false;
    private $messages = 0;

    public function __construct(Platform $platform, ?\Symfony\Component\Routing\RouterInterface $router = null)
    {
        $this->platform = $platform;
        $this->router = $router;
    }

    public static function getSubscribedEvents(): array
    {
        return array(
            'kernel.request' => array(
                // Above the router (32), the session (128) and the security firewall (8).
                array('onRequest', 4096),
                // Just after the router: the route is known, the security firewall hasn't run.
                array('onRouted', 31),
            ),
            // Late, so headers the app or another bundle sets are already there and win.
            'kernel.response' => array('onResponse', -1024),
            'kernel.exception' => array('onException', 2048),
            'kernel.terminate' => array('onTerminate', -1024),
            'console.error' => array('onConsoleError', 0),
            'console.terminate' => array('onConsoleTerminate', -1024),
            // Last, so a listener that tells the worker to skip a message has spoken.
            'Symfony\\Component\\Messenger\\Event\\WorkerMessageReceivedEvent' => array('onMessageReceived', -1024),
            'Symfony\\Component\\Messenger\\Event\\WorkerMessageHandledEvent' => array('onMessageHandled', 0),
            'Symfony\\Component\\Messenger\\Event\\WorkerMessageFailedEvent' => array('onMessageFailed', 0),
            'Symfony\\Component\\Messenger\\Event\\WorkerRunningEvent' => array('onWorkerRunning', 0),
            'Symfony\\Component\\Security\\Http\\Event\\LoginFailureEvent' => array('onLoginFailure', 0),
            'security.interactive_login' => array('onLogin', 0),
            'Symfony\\Component\\Security\\Http\\Event\\LogoutEvent' => array('onLogout', 0),
        );
    }

    public function onRequest($event)
    {
        if (!$event->isMainRequest() || !$this->platform->configured()) {
            return;
        }
        $request = $event->getRequest();
        $request->attributes->set(self::STARTED, microtime(true));
        // A worker's queries from here on are this request's (QueryMiddleware).
        $this->platform->beginRequest();
        $ip = (string) $request->getClientIp();
        $this->platform->setClientIp($ip);
        // For a request that never reaches kernel.terminate (its error page
        // failed too): its exception is waiting by the time this runs.
        if (!$this->shutdown) {
            $this->shutdown = true;
            register_shutdown_function(array($this, 'onShutdown'));
        }
        // The tracker's own addresses, answered before anything else: a
        // visitor's beacon is our traffic, not a page of the site, so it
        // isn't timed, counted as a crawler or rate-limited. Matched first, so
        // no other request's body is read.
        $proxy = $this->platform->proxy();
        if ($proxy !== null && $proxy->match($request->getPathInfo()) !== null) {
            $headers = array();
            foreach ($request->headers->all() as $name => $values) {
                $headers[$name] = implode(', ', (array) $values);
            }
            $served = $this->platform->proxyResponse(
                $request->getPathInfo(),
                $request->getMethod(),
                (string) $request->getQueryString(),
                $headers,
                $request->getContent(),
                $ip
            );
            $request->attributes->set(self::PROXIED, true);
            $event->setResponse(new Response($served['body'], $served['status'], $served['headers']));
            return;
        }
        $only = $this->only();
        if ($only === null || self::pathListed($only, $request->getPathInfo())) {
            $this->protect($event, $request);
        }
    }

    // With 'protect_only', the routes it names by name; and for every request
    // the route's path, so errors captured during it carry it.
    public function onRouted($event)
    {
        if (!$event->isMainRequest() || !$this->platform->configured() || $event->getRequest()->attributes->get(self::PROXIED)) {
            return;
        }
        $request = $event->getRequest();
        $route = $this->routePattern($request);
        $request->attributes->set(self::ROUTE, $route);
        $this->platform->setRoute($route);
        $only = $this->only();
        if ($only !== null && !$request->attributes->get(self::CHECKED)
            && self::routeListed($only, (string) $request->attributes->get('_route'))) {
            $this->protect($event, $request);
        }
    }

    // The firewall, then maintenance mode; a response ends the request.
    private function protect($event, $request)
    {
        $request->attributes->set(self::CHECKED, true);
        $firewall = $this->platform->firewall();
        if ($firewall) {
            try {
                $decision = $firewall->check((string) $request->getClientIp(), $request->getMethod(), $request->getRequestUri(),
                    (string) $request->headers->get('User-Agent'), (string) $request->headers->get('Accept'),
                    // Every Cookie header: a server may pass a second one apart.
                    Challenge::cookieValues(Challenge::cookieHeaderOf($request->headers->all())));
                // The browser check: its page sets the pass and reloads.
                $page = $decision['rule'] === 'challenge' ? $firewall->challengePage((string) $request->getClientIp(), $request->getMethod()) : null;
            } catch (\Throwable $e) {
                return;
            }
            if ($decision['action'] === 'block' && $page !== null) {
                $request->attributes->set(self::CHECK_PAGE, $page['headers']);
                $event->setResponse(new Response($page['body'], $page['status'], $page['headers']));
                return;
            }
            if ($decision['action'] === 'block') {
                $headers = array('Content-Type' => 'text/plain; charset=utf-8', 'Cache-Control' => 'no-store');
                $rules = $firewall->status();
                if ($decision['status'] === 429 && !empty($rules['rate'])) {
                    $headers['Retry-After'] = (string) $rules['rate']['window'];
                }
                $event->setResponse(new Response($decision['status'] === 429 ? 'Too Many Requests' : 'Forbidden', $decision['status'], $headers));
                return;
            }
        }
        $page = $this->platform->maintenancePage(method_exists($request, 'isSecure') ? $request->isSecure() : null);
        if ($page !== null) {
            $event->setResponse(new Response($page, 503, array(
                'Content-Type' => 'text/html; charset=utf-8', 'Retry-After' => '600', 'Cache-Control' => 'no-store',
            )));
        }
    }

    // 'protect_only': paths ("/admin", every address below it) and route
    // names ("checkout", or "admin_*" for all that start so); null: everything.
    private function only()
    {
        $only = $this->platform->core()->opt('protect_only');
        return is_array($only) && $only ? array_values(array_map('strval', $only)) : null;
    }

    public static function pathListed(array $only, $path)
    {
        $path = (string) $path;
        foreach ($only as $entry) {
            if ($entry !== '' && $entry[0] === '/') {
                $prefix = rtrim($entry, '/');
                if ($prefix === '' || $path === $prefix || strpos($path, $prefix . '/') === 0) {
                    return true;
                }
            }
        }
        return false;
    }

    public static function routeListed(array $only, $name)
    {
        if ($name === '') {
            return false;
        }
        foreach ($only as $entry) {
            if ($entry === '' || $entry[0] === '/') {
                continue;
            }
            if ($entry === $name || (substr($entry, -1) === '*' && strpos($name, substr($entry, 0, -1)) === 0)) {
                return true;
            }
        }
        return false;
    }

    public function onResponse($event)
    {
        if (!$event->isMainRequest() || $event->getRequest()->attributes->get(self::PROXIED)) {
            return;
        }
        $headers = $event->getResponse()->headers;
        $check = $event->getRequest()->attributes->get(self::CHECK_PAGE);
        if (is_array($check)) {
            foreach ($check as $name => $value) {
                $headers->set($name, $value);
            }
        }
        foreach ($this->platform->securityHeaders() as $pair) {
            if (!$headers->has($pair[0])) {
                $headers->set($pair[0], $pair[1]);
            }
        }
    }

    // Kept, not sent: whether it is an error depends on the response it
    // becomes, which Symfony's framework.exceptions and #[WithHttpStatus], or
    // another bundle's listener, may make a 404.
    public function onException($event)
    {
        if ($event->isMainRequest() && $this->exception === null) {
            $this->exception = $event->getThrowable();
            $this->request = $event->getRequest();
        }
    }

    public function onTerminate($event)
    {
        $request = $event->getRequest();
        $exception = $this->exception;
        $this->exception = null;
        $this->request = null;
        // A proxied beacon is our traffic, not the site's: it isn't timed.
        if (!$this->platform->configured() || $request->attributes->get(self::PROXIED)) {
            $this->reset();
            return;
        }
        $status = (int) $event->getResponse()->getStatusCode();
        $route = $this->routePattern($request);
        // Timing and crawlers read the request from $_SERVER, which a worker
        // may already have replaced (FrankenPHP calls terminate after it) or
        // never filled (RoadRunner, Swoole): this request's own stands in for
        // it while they run.
        $server = $_SERVER;
        $_SERVER = self::serverOf($request);
        try {
            // A fatal error Symfony turned into an exception is read again by
            // the errors module below (as plain PHP sends it), so it is left to that.
            if ($exception !== null && $status >= 500 && !$exception instanceof \Symfony\Component\ErrorHandler\Error\FatalError) {
                $this->platform->captureException($exception, self::requestFields($request, $route), $status, 'error');
            }
            // Server speed: the route's path and the status the visitor got.
            $this->platform->setRoute($route);
            if (!headers_sent() || (int) http_response_code() !== $status) {
                @http_response_code($status);
            }
            $this->platform->recordAndSend();
        } finally {
            $_SERVER = $server;
        }
        $this->reset();
    }

    // $_SERVER as PHP-FPM would have it for this request.
    public static function serverOf($request)
    {
        $server = $request->server->all();
        foreach ($request->headers->all() as $name => $values) {
            $server['HTTP_' . strtoupper(str_replace('-', '_', $name))] = implode(', ', (array) $values);
        }
        $server['REQUEST_METHOD'] = $request->getMethod();
        $server['REQUEST_URI'] = $request->getRequestUri();
        if (empty($server['REQUEST_TIME_FLOAT']) && $request->attributes->get(self::STARTED)) {
            $server['REQUEST_TIME_FLOAT'] = $request->attributes->get(self::STARTED);
        }
        return $server;
    }

    // Between requests in a worker (kernel.reset), and after each one.
    public function reset()
    {
        $this->exception = null;
        $this->request = null;
        $this->platform->setRoute('');
        $this->platform->clearBreadcrumbs();
        $this->platform->setClientIp(null);
    }

    // The request ended without kernel.terminate: its exception, if it was
    // one, and anything else waiting are sent now.
    public function onShutdown()
    {
        if ($this->exception !== null) {
            $status = self::statusOf($this->exception);
            if ($status >= 500) {
                $this->platform->captureException($this->exception, self::requestFields($this->request, $this->routePattern($this->request)), $status, 'error');
            }
            $this->exception = null;
        }
        $this->platform->sendErrors();
    }

    // The status an exception means: an HTTP exception's own, else 500.
    public static function statusOf($error)
    {
        return $error instanceof \Symfony\Component\HttpKernel\Exception\HttpExceptionInterface ? (int) $error->getStatusCode() : 500;
    }

    // A command that ended with an exception, named as a job is. A mistyped
    // command or a missing argument is the console's own answer, not an error.
    public function onConsoleError($event)
    {
        $error = $event->getError();
        if ($error instanceof \Symfony\Component\Console\Exception\ExceptionInterface) {
            return;
        }
        $route = '/(job) ' . substr($event->getCommand() ? (string) $event->getCommand()->getName() : 'console', 0, 180);
        $this->platform->captureException($error, array('method' => 'JOB', 'path' => $route, 'route' => $route, 'session_id' => ''), 500, 'error');
    }

    // What a command captured (its failure, the exceptions it logged) is sent
    // as it ends, once: one logged and then thrown is the error it became.
    public function onConsoleTerminate($event)
    {
        $this->platform->sendErrors();
    }

    public function onMessageReceived($event)
    {
        if (method_exists($event, 'shouldHandle') && !$event->shouldHandle()) {
            return;
        }
        $this->messages++;
        $this->platform->startJob(get_class($event->getEnvelope()->getMessage()));
    }

    public function onMessageHandled($event)
    {
        if ($this->messages > 0) {
            $this->messages--;
            $this->platform->endJob(false);
        }
    }

    // Each turn of the worker's loop, also when it found nothing to do: what
    // was captured outside a message (an exception logged while it started,
    // or between messages) is sent now, not when the next message ends.
    public function onWorkerRunning($event)
    {
        if ($this->messages === 0) {
            $this->platform->sendErrors();
        }
    }

    // Each failed try, as Laravel's JobExceptionOccurred; the handler's own
    // exception, not Messenger's wrapper around it.
    public function onMessageFailed($event)
    {
        if ($this->messages > 0) {
            $this->messages--;
        } else {
            $this->platform->startJob(get_class($event->getEnvelope()->getMessage()));
        }
        $error = $event->getThrowable();
        if ($error instanceof \Symfony\Component\Messenger\Exception\HandlerFailedException && $error->getPrevious()) {
            $error = $error->getPrevious();
        }
        $this->platform->captureException($error, null, 500, 'error');
        $this->platform->endJob(true);
    }

    // A person's login (a form, JSON), not an API token: an app whose
    // token ran out would otherwise get its users banned.
    public function onLoginFailure($event)
    {
        $authenticator = $event->getAuthenticator();
        if ($authenticator instanceof \Symfony\Component\Security\Http\Authenticator\InteractiveAuthenticatorInterface && $authenticator->isInteractive()) {
            $this->platform->loginFailed((string) $event->getRequest()->getClientIp());
        }
    }

    public function onLogin($event)
    {
        $this->platform->audit('user.login', self::userOf($event->getAuthenticationToken()));
    }

    public function onLogout($event)
    {
        $this->platform->audit('user.logout', self::userOf($event->getToken()));
    }

    private static function userOf($token)
    {
        return $token && method_exists($token, 'getUserIdentifier') ? (string) $token->getUserIdentifier() : '';
    }

    // The request as the Errors report and Server speed name it. The visit
    // is read as Platform::sessionIdFromRequest() reads it, from the Request.
    public static function requestFields($request, $route)
    {
        if (!$request) {
            return array('method' => '', 'path' => '', 'route' => (string) $route, 'session_id' => '');
        }
        $session = (string) ($request->headers->get('X-Analytics-Session') ?: $request->cookies->get(Platform::SESSION_COOKIE));
        return array(
            'method' => $request->getMethod(),
            'path' => $request->getPathInfo(),
            'route' => (string) $route,
            'session_id' => preg_match('/^[0-9a-f-]{36}$/Di', $session) ? strtolower($session) : '',
        );
    }

    // ---- Route paths ------------------------------------------------------
    // Symfony keeps only the matched route's name on the request. Its path
    // ("/users/{id}") is in the route collection, which Symfony says never to
    // load at runtime (it reads every route file and controller), so it is
    // loaded once and kept as name => path in a PHP file next to the router's
    // cache. cache:clear removes it with the rest; in debug mode it is made
    // again whenever the router's own cache is newer.

    // The matched route's path, or '' (no route matched: a 404).
    public function routePattern($request)
    {
        $name = $request ? $request->attributes->get('_route') : null;
        if (!is_string($name) || $name === '' || !$this->router) {
            return '';
        }
        try {
            $paths = $this->routePaths(false);
            if (!array_key_exists($name, $paths)) {
                $paths = $this->routePaths(true, $name);
            }
            return isset($paths[$name]) ? (string) $paths[$name] : '';
        } catch (\Throwable $e) {
            return '';
        }
    }

    private function routesFile()
    {
        if (!method_exists($this->router, 'getOption')) {
            return null;
        }
        $dir = $this->router->getOption('cache_dir');
        return $dir ? rtrim((string) $dir, '/\\') . '/' . self::ROUTES_FILE : null;
    }

    // $missing: a name the collection doesn't have either is kept as '', so
    // it isn't looked for on every request.
    private function routePaths($rebuild, $missing = null)
    {
        $file = $this->routesFile();
        if (!$rebuild) {
            if ($this->paths !== null && !($file !== null && $this->stale($file))) {
                return $this->paths;
            }
            if ($file !== null && is_file($file) && !$this->stale($file)) {
                $saved = @include $file;
                if (is_array($saved)) {
                    return $this->paths = $saved;
                }
            }
        }
        $paths = array();
        foreach ($this->router->getRouteCollection()->all() as $name => $route) {
            $paths[$name] = $route->getPath();
        }
        if ($missing !== null && !isset($paths[$missing])) {
            $paths[$missing] = '';
        }
        if ($file !== null) {
            self::write($file, $paths);
        }
        return $this->paths = $paths;
    }

    private function stale($file)
    {
        if (!method_exists($this->router, 'getOption') || !$this->router->getOption('debug')) {
            return false;
        }
        $matcher = dirname($file) . '/url_matching_routes.php';
        clearstatcache(true, $matcher);
        clearstatcache(true, $file);
        return is_file($matcher) && (!is_file($file) || filemtime($matcher) > filemtime($file));
    }

    private static function write($file, array $paths)
    {
        $tmp = $file . '.' . getmypid() . '.tmp';
        $php = "<?php\n// Written by the analytics package: route name => path, for Server speed.\nreturn " . var_export($paths, true) . ";\n";
        if (@file_put_contents($tmp, $php, LOCK_EX) === false || !@rename($tmp, $file)) {
            @unlink($tmp);
            return;
        }
        if (function_exists('opcache_invalidate')) {
            @opcache_invalidate($file, true);
        }
    }

    // cache:warmup writes the paths while the cache folder can be written, for
    // a deploy that makes it read-only afterwards.
    public function isOptional(): bool
    {
        return true;
    }

    public function warmUp($cacheDir, $buildDir = null): array
    {
        if ($this->router) {
            try {
                $this->routePaths(true);
            } catch (\Throwable $e) {
                // the first request makes them instead
            }
        }
        return array();
    }
}
