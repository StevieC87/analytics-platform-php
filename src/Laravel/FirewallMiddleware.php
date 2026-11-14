<?php
// Checks each request with $request->ip(), so Laravel's trusted proxies
// decide the visitor's address, for the firewall and for everything else the
// platform does with it (maintenance allow list, forms, audit, crawlers). Errors, events, rules and module switches
// are sent and synced after the response (terminate).

namespace AnalyticsPlatform\Laravel;

use AnalyticsPlatform\Challenge;
use AnalyticsPlatform\Platform;
use Closure;

class FirewallMiddleware
{
    // Marks a request answered by the proxy, so terminate() leaves it alone.
    const PROXIED = 'analytics-platform.proxied';
    // When handle() saw the request, for a server that doesn't say (Octane).
    const STARTED = 'analytics-platform.started';

    private $platform;

    public function __construct(Platform $platform)
    {
        $this->platform = $platform;
    }

    public function handle($request, Closure $next)
    {
        $request->attributes->set(self::STARTED, microtime(true));
        $this->platform->setClientIp((string) $request->ip());
        // The tracker's own addresses, answered before anything else: a
        // visitor's beacon is our traffic, not a page of the site, so it
        // isn't timed, counted as a crawler or rate-limited. Matched first,
        // so no other request's body is read, and with this request's own
        // headers: under Octane $_SERVER is the worker's, not the visitor's.
        $proxy = $this->platform->proxy();
        if ($proxy !== null && $proxy->match($request->getPathInfo()) !== null) {
            $headers = array();
            foreach ($request->headers->all() as $name => $values) {
                $headers[$name] = implode(', ', (array) $values);
            }
            $served = $this->platform->proxyResponse(
                $request->getPathInfo(),
                $request->method(),
                (string) $request->getQueryString(),
                $headers,
                $request->getContent(),
                (string) $request->ip()
            );
            if ($served !== null) {
                $request->attributes->set(self::PROXIED, true);
                return response($served['body'], $served['status'], $served['headers']);
            }
        }
        return $this->withHeaders($this->check($request, $next));
    }

    // Security headers the response doesn't set itself.
    private function withHeaders($response)
    {
        if (is_object($response) && isset($response->headers)) {
            foreach ($this->platform->securityHeaders() as $pair) {
                if (!$response->headers->has($pair[0])) {
                    $response->headers->set($pair[0], $pair[1]);
                }
            }
        }
        return $response;
    }

    private function check($request, Closure $next)
    {
        $firewall = $this->platform->firewall();
        if (!$firewall || !$this->platform->configured()) {
            return $this->open($request, $next);
        }
        try {
            $decision = $firewall->check(
                (string) $request->ip(),
                $request->method(),
                $request->getRequestUri(),
                (string) $request->userAgent(),
                (string) $request->headers->get('Accept'),
                // From the Cookie header itself: past EncryptCookies (the
                // middleware on a route group), the cookie bag holds null for
                // a cookie Laravel didn't encrypt, as this one is set by script.
                // Every Cookie header: a server may pass a second one apart.
                Challenge::cookieValues(Challenge::cookieHeaderOf($request->headers->all())),
                // Another site's page made the browser ask: refused, never banned.
                (string) $request->headers->get('Sec-Fetch-Site')
            );
            // The browser check: its page sets the pass and reloads.
            $page = $decision['rule'] === 'challenge' ? $firewall->challengePage((string) $request->ip(), $request->method()) : null;
        } catch (\Throwable $e) {
            return $next($request);
        }
        if ($decision['action'] !== 'block') {
            return $this->open($request, $next);
        }
        if ($page !== null) {
            return response($page['body'], $page['status'], $page['headers']);
        }
        // A page limit's Retry-After is its own window, not the rate's.
        $answer = $firewall->blockedResponse($decision);
        return response($answer['body'], $answer['status'], $answer['headers']);
    }

    // Maintenance mode's page, else the app.
    private function open($request, Closure $next)
    {
        $page = $this->platform->maintenancePage(method_exists($request, 'isSecure') ? $request->isSecure() : null);
        if ($page === null) {
            return $next($request);
        }
        return response($page, 503)->header('Content-Type', 'text/html; charset=utf-8')
            ->header('Retry-After', '600')->header('Cache-Control', 'no-store');
    }

    public function terminate($request, $response)
    {
        // A proxied beacon is our traffic, not the site's: it isn't timed.
        if (!$this->platform->configured() || $request->attributes->get(self::PROXIED)) {
            $this->reset();
            return;
        }
        // The platform reads the request's start time, user agent and the
        // rest from $_SERVER. Under Octane (Swoole, RoadRunner, FrankenPHP)
        // that is the worker's, filled once or never, so this request's own
        // is put there while it is recorded, and the worker's put back.
        $server = $_SERVER;
        $_SERVER = self::serverOf($request);
        try {
            // Server speed: Laravel's route pattern ("/orders/{order}") and the real status.
            $route = $request->route();
            if ($route) {
                $this->platform->setRoute('/' . ltrim($route->uri(), '/'));
            }
            $status = null;
            if (method_exists($response, 'getStatusCode')) {
                $status = (int) $response->getStatusCode();
                if (!headers_sent() || http_response_code() !== $status) {
                    @http_response_code($status);
                }
            }
            // A static-looking request Laravel routed to a page
            // ("search/{q}" took "/search/x.css") counts toward the rate and
            // the page limits after all (firewall.md, `rate`).
            $firewall = $this->platform->firewall();
            if ($firewall) {
                $type = is_object($response) && isset($response->headers) ? $response->headers->get('Content-Type') : null;
                $firewall->markRouted(self::routedToPage($route), $type);
                // Counted now, by the response's own status: under Octane no
                // shutdown follows the request and http_response_code() is
                // the worker's, not this response's.
                $firewall->countStatic($status);
            }
            $this->platform->recordAndSend();
        } finally {
            $_SERVER = $server;
        }
        $this->reset();
    }

    // Whether $route (the request's, or null) is a page of the app's: not a
    // route that is itself a file's ("avatars/{id}.png"), nor the ones
    // Laravel and Livewire serve files from (storage/ for the local disk's
    // files, livewire/ for its script and uploaded previews): an image on a
    // page is a request to one.
    public static function routedToPage($route)
    {
        if (!$route || !method_exists($route, 'uri')) {
            return false;
        }
        $uri = '/' . ltrim((string) $route->uri(), '/');
        if (strpos($uri, '/storage/') === 0 || strpos($uri, '/livewire/') === 0 || strpos($uri, '/livewire-') === 0) {
            return false;
        }
        return !\AnalyticsPlatform\Firewall::isStatic($uri);
    }

    // A long-lived worker (Octane) serves the next visitor with this same
    // Platform, so nothing of this request is left on it.
    private function reset()
    {
        $this->platform->setRoute('');
        $this->platform->clearBreadcrumbs();
        $this->platform->setClientIp(null);
    }

    // $_SERVER as this request saw it: its server values and its headers.
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
}
