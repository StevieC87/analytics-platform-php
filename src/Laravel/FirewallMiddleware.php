<?php
// Checks each request with $request->ip(), so Laravel's trusted proxies
// decide the visitor's address, for the firewall and for everything else the
// platform does with it (maintenance allow list, forms, audit, crawlers). Errors, events, rules and module switches
// are sent and synced after the response (terminate).

namespace AnalyticsPlatform\Laravel;

use AnalyticsPlatform\Platform;
use Closure;

class FirewallMiddleware
{
    // Marks a request answered by the proxy, so terminate() leaves it alone.
    const PROXIED = 'analytics-platform.proxied';

    private $platform;

    public function __construct(Platform $platform)
    {
        $this->platform = $platform;
    }

    public function handle($request, Closure $next)
    {
        $this->platform->setClientIp((string) $request->ip());
        // The tracker's own addresses, answered before anything else: a
        // visitor's beacon is our traffic, not a page of the site, so it
        // isn't timed, counted as a crawler or rate-limited.
        $served = $this->platform->proxyResponse(
            $request->getPathInfo(),
            $request->method(),
            (string) $request->getQueryString(),
            null,
            $request->getContent(),
            (string) $request->ip()
        );
        if ($served !== null) {
            $request->attributes->set(self::PROXIED, true);
            return response($served['body'], $served['status'], $served['headers']);
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
                (string) $request->userAgent()
            );
        } catch (\Throwable $e) {
            return $next($request);
        }
        if ($decision['action'] !== 'block') {
            return $this->open($request, $next);
        }
        $response = response($decision['status'] === 429 ? 'Too Many Requests' : 'Forbidden', $decision['status'])
            ->header('Content-Type', 'text/plain; charset=utf-8')
            ->header('Cache-Control', 'no-store');
        $rules = $firewall->status();
        if ($decision['status'] === 429 && !empty($rules['rate'])) {
            $response->header('Retry-After', (string) $rules['rate']['window']);
        }
        return $response;
    }

    // Maintenance mode's page, else the app.
    private function open($request, Closure $next)
    {
        $page = $this->platform->maintenancePage();
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
            $this->platform->setClientIp(null);
            return;
        }
        // Server speed: Laravel's route pattern ("/orders/{order}") and the real status.
        $route = $request->route();
        if ($route) {
            $this->platform->setRoute('/' . ltrim($route->uri(), '/'));
        }
        if (method_exists($response, 'getStatusCode')) {
            http_response_code($response->getStatusCode());
        }
        $this->platform->recordAndSend();
        // A long-lived worker (Octane) serves the next visitor with this same Platform.
        $this->platform->setClientIp(null);
    }
}
