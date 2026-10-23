<?php
// One package for a PHP site's server, run from the analytics dashboard:
// firewall, error monitoring, server analytics and the rest. Each module is separate:
// only the ones turned on are created, and the firewall never waits on
// reporting. A module can also be switched off in the dashboard (Site
// settings → Server). Everything that talks to the collector runs after the
// response has gone out (PHP-FPM), so visitors never wait on it.
//
//   $platform = new AnalyticsPlatform\Platform([
//       'site_id' => '...', 'secret' => getenv('ANALYTICS_SITE_SECRET'), 'endpoint' => 'https://...',
//   ]);
//   $platform->protect(); // as early as possible, before any output

namespace AnalyticsPlatform;

class Platform
{
    const SESSION_HEADER = 'HTTP_X_ANALYTICS_SESSION';
    // Set by the tracker's page script in the WordPress plugin, for requests
    // that can't send the header (form posts, checkouts).
    const SESSION_COOKIE = 'analytics_session';

    private $core;
    private $options;
    private $modules = array();
    private $protected = false;

    // Options: site_id, secret, endpoint (required); storage, platform (see
    // Core); trust_proxy, mode, counter, on_block (see Firewall); and per
    // module 'firewall' / 'errors' / 'analytics' / 'performance' => true, false
    // or an array of that module's options (errors: server_name, root,
    // before_send; performance: server_name; files: roots and the rest, see
    // Files; off unless given; inventory: root and the rest, see Inventory;
    // posture: roots and the callbacks, see Posture).
    public function __construct(array $options)
    {
        $this->core = new Core($options);
        $this->options = $options;
        foreach (array('proxy', 'firewall', 'errors', 'analytics', 'performance', 'crawlers', 'forms', 'headers', 'audit', 'flags', 'maintenance', 'files', 'inventory', 'posture', 'resources') as $name) {
            // File monitoring needs its folders, and the set-up checks walk the
            // web folder once a day: both are off unless asked for. (The
            // WordPress plugin asks for them.)
            $setting = array_key_exists($name, $options) ? $options[$name] : !in_array($name, array('files', 'posture'), true);
            if ($setting === false || $setting === null) {
                continue;
            }
            $own = is_array($setting) ? $setting : array();
            try {
                if ($name === 'proxy') {
                    $this->modules[$name] = new Proxy(
                        $this->core->opt('endpoint'),
                        $this->core->opt('secret'),
                        $this->core->dir(),
                        isset($own['prefix']) ? $own['prefix'] : ''
                    );
                } elseif ($name === 'firewall') {
                    $this->modules[$name] = new Firewall($own + $options, $this->core);
                } elseif ($name === 'errors') {
                    $this->modules[$name] = new Errors($this->core, $own);
                } elseif ($name === 'performance') {
                    $this->modules[$name] = new Performance($this->core, $own);
                } elseif ($name === 'resources') {
                    $this->modules[$name] = new Resources($this->core, $own);
                } elseif ($name === 'crawlers') {
                    $this->modules[$name] = new Crawlers($this->core, $own);
                } elseif ($name === 'forms') {
                    $this->modules[$name] = new Forms($this->core);
                } elseif ($name === 'files') {
                    $this->modules[$name] = new Files($this->core, $own);
                } elseif ($name === 'inventory') {
                    $this->modules[$name] = new Inventory($this->core, $own);
                } elseif ($name === 'posture') {
                    $this->modules[$name] = new Posture($this->core, $own);
                } elseif ($name === 'audit') {
                    $this->modules[$name] = new Audit($this->core);
                } elseif ($name === 'flags' || $name === 'maintenance') {
                    // From the module switches (Core); see Flags.
                    $this->modules[$name] = true;
                } elseif ($name === 'headers') {
                    // The headers come with the module switches (Core).
                    $this->modules[$name] = true;
                } else {
                    $this->modules[$name] = new Analytics($this->core);
                }
            } catch (\Throwable $e) {
                // that module stays off
            }
        }
        $this->core->setLoaded(array_keys($this->modules));
    }

    public function configured()
    {
        return $this->core->configured();
    }

    public function modules()
    {
        return array_keys($this->modules);
    }

    // The shared Core: credentials, the storage folder and sending. The
    // WordPress plugin's first-party proxy needs the folder's name, which
    // hashes the secret and so can't be worked out anywhere else.
    public function core()
    {
        return $this->core;
    }

    public function module($name)
    {
        return isset($this->modules[$name]) ? $this->modules[$name] : null;
    }

    public function firewall()
    {
        return $this->module('firewall');
    }

    // The browser's visit: the X-Analytics-Session header, else the cookie.
    public static function sessionIdFromRequest()
    {
        $value = !empty($_SERVER[self::SESSION_HEADER]) ? $_SERVER[self::SESSION_HEADER]
            : (!empty($_COOKIE[self::SESSION_COOKIE]) ? $_COOKIE[self::SESSION_COOKIE] : '');
        return preg_match('/^[0-9a-f-]{36}$/i', (string) $value) ? strtolower($value) : '';
    }

    // Checks the request with the firewall (and ends it when blocked), starts
    // catching errors, and sends everything after the response.
    public function protect()
    {
        if ($this->protected || !$this->core->configured() || PHP_SAPI === 'cli') {
            return;
        }
        // The tracker's own addresses, answered before anything else and
        // without the rest of the request: a visitor's beacon is our traffic,
        // not a page of the site, so it shouldn't be timed, counted as a
        // crawler or turned away by the firewall's rate limit.
        if ($this->serveProxy()) {
            exit;
        }
        $this->protected = true;
        register_shutdown_function(array($this, 'afterResponse'));
        if (isset($this->modules['errors']) && $this->core->isOn('errors')) {
            $this->modules['errors']->install();
        }
        // Security headers, sent first: a header the site sets later replaces ours.
        if (!headers_sent()) {
            foreach ($this->securityHeaders() as $pair) {
                header($pair[0] . ': ' . $pair[1]);
            }
        }
        if (isset($this->modules['firewall'])) {
            // Its own shutdown work runs from afterResponse() below.
            $this->modules['firewall']->protect(false);
        }
        // Maintenance mode, unless the caller checks it itself (the WordPress
        // plugin does, so wp-admin and logins keep working).
        if (empty($this->options['maintenance_manual'])) {
            $this->sendMaintenancePage();
        }
    }

    // The first-party proxy, so ad blockers can't hide visitors:
    // $platform->proxy()->scriptUrl() and ->collectUrl() are the two
    // addresses the page's script tag needs, on this site's own domain.
    public function proxy()
    {
        return isset($this->modules['proxy']) && $this->core->isOn('proxy') ? $this->modules['proxy'] : null;
    }

    // True when the request was the tracker's and has been answered. Called
    // by protect(); a framework asks proxyResponse() for the answer instead.
    private function serveProxy()
    {
        $answer = $this->proxyResponse(
            isset($_SERVER['REQUEST_URI']) ? explode('?', $_SERVER['REQUEST_URI'], 2)[0] : '',
            isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : 'GET',
            isset($_SERVER['QUERY_STRING']) ? $_SERVER['QUERY_STRING'] : '',
            null,
            null
        );
        if ($answer === null) {
            return false;
        }
        $this->modules['proxy']->respond($answer);
        return true;
    }

    // The answer when the address belongs to the proxy, else null. $headers
    // and $body default to this request's; a framework passes its own.
    public function proxyResponse($path, $method = 'GET', $query = '', array $headers = null, $body = null, $ip = null)
    {
        $proxy = $this->proxy();
        if ($proxy === null) {
            return null;
        }
        $found = $proxy->match($path);
        if ($found === null) {
            return null;
        }
        if ($headers === null) {
            $headers = array();
            foreach ($_SERVER as $key => $value) {
                if (strncmp($key, 'HTTP_', 5) === 0) {
                    $headers[strtolower(str_replace('_', '-', substr($key, 5)))] = $value;
                }
            }
            if (!empty($_SERVER['CONTENT_TYPE'])) {
                $headers['content-type'] = $_SERVER['CONTENT_TYPE'];
            }
        }
        if ($body === null && strtoupper($method) === 'POST') {
            $body = file_get_contents('php://input', false, null, 0, Proxy::MAX_BODY + 1);
        }
        if ($ip === null) {
            $firewall = isset($this->modules['firewall']) ? $this->modules['firewall'] : null;
            $ip = $firewall ? $firewall->clientIp() : (isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '');
        }
        try {
            return $proxy->handle($found[0], $found[1], $method, $query, $headers, $body, $ip);
        } catch (\Throwable $e) {
            return array('status' => 502, 'headers' => array(), 'body' => '');
        }
    }

    // The request's route pattern for Server speed, e.g. "/orders/{id}".
    public function setRoute($route)
    {
        if (isset($this->modules['performance'])) {
            $this->modules['performance']->setRoute($route);
        }
    }

    public function captureException($error, $request = null, $status = 0, $kind = 'handled')
    {
        if (isset($this->modules['errors'])) {
            $this->modules['errors']->captureException($error, $request, $status, $kind);
        }
    }

    // A feature flag from the dashboard ($user: for rollouts and user lists;
    // $default: until the flag is known, or with the module off).
    public function isEnabled($key, $user = null, $default = false)
    {
        if (!isset($this->modules['flags'])) {
            return $default;
        }
        $flags = $this->core->flags();
        return isset($flags[$key]) && is_array($flags[$key]) ? Flags::evaluate($flags[$key], (string) $key, $user) : $default;
    }

    // Maintenance mode's page for this request, or null to let it through.
    public function maintenancePage()
    {
        if (!isset($this->modules['maintenance']) || PHP_SAPI === 'cli') {
            return null;
        }
        $ip = isset($this->modules['firewall']) ? $this->modules['firewall']->clientIp() : (isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '');
        return Flags::maintenancePage($this->core->maintenance(), $ip);
    }

    // Sends maintenance mode's page and ends the request, when it applies.
    public function sendMaintenancePage()
    {
        $page = $this->maintenancePage();
        if ($page === null) {
            return;
        }
        if (!headers_sent()) {
            http_response_code(503);
            header('Retry-After: 600');
            header('Cache-Control: no-store');
            header('Content-Type: text/html; charset=utf-8');
        }
        echo $page;
        exit;
    }

    // Audit log: records who did what (sent after the response).
    public function audit($action, $actor = '', $target = '', $details = null)
    {
        if (!isset($this->modules['audit'])) {
            return;
        }
        $ip = isset($this->modules['firewall']) ? $this->modules['firewall']->clientIp() : (isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '');
        $this->modules['audit']->record($action, $actor, $target, $details, PHP_SAPI === 'cli' ? '' : $ip);
    }

    // The dashboard's security headers, as array(name, value) pairs.
    public function securityHeaders()
    {
        return isset($this->modules['headers']) ? $this->core->securityHeaders() : array();
    }

    // Form protection: checks a form before you accept it (default: $_POST).
    // Returns array('ok', 'spam', 'reasons', 'checked'); spam goes to Leads → Spam.
    public function checkForm($fields = null, $email = null, $name = null, $form = null)
    {
        if (!isset($this->modules['forms'])) {
            return array('ok' => true, 'spam' => false, 'reasons' => array(), 'checked' => false);
        }
        $ip = isset($this->modules['firewall']) ? $this->modules['firewall']->clientIp() : (isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '');
        try {
            return $this->modules['forms']->check(is_array($fields) ? $fields : $_POST, $ip, $email, $name, $form);
        } catch (\Throwable $e) {
            return array('ok' => true, 'spam' => false, 'reasons' => array('unchecked'), 'checked' => false);
        }
    }

    // File monitoring: checks the files when due (or now, $force) and reports
    // what changed. From a cron job, never a visitor's request. $accept: the
    // files as they are now are the accepted version (after a deploy).
    public function checkFiles($force = false, $accept = false)
    {
        $files = $this->module('files');
        if (!$files || !$this->core->isOn('files') || (!$force && !$accept && !$files->due())) {
            return array();
        }
        try {
            return $files->run($accept);
        } catch (\Throwable $e) {
            return array();
        }
    }

    // Software inventory: reports the site's packages and runtime when due
    // (or now, $force). Platform does it after responses on its own unless
    // the module's 'manual' option is set (then from your cron job).
    public function checkInventory($force = false)
    {
        $inventory = $this->module('inventory');
        if (!$inventory || !$this->core->isOn('inventory') || (!$force && !$inventory->due())) {
            return array();
        }
        try {
            return $inventory->run();
        } catch (\Throwable $e) {
            return array();
        }
    }

    // How the site is set up (sdk/protocols/posture.md): reports when due (or
    // now, $force). It rides the inventory switch, so a site with software
    // inventory off reports no posture either. Returns the checks that failed.
    public function checkPosture($force = false)
    {
        $posture = $this->module('posture');
        if (!$posture || !$this->core->isOn('inventory') || (!$force && !$posture->due())) {
            return array();
        }
        try {
            return $posture->run();
        } catch (\Throwable $e) {
            return array();
        }
    }

    // A failed login (bot protection); default: the current visitor's address.
    public function loginFailed($ip = null)
    {
        if (isset($this->modules['firewall'])) {
            $this->modules['firewall']->loginFailed($ip);
        }
    }

    public function track($name, array $fields = array(), $sessionId = null)
    {
        return isset($this->modules['analytics']) ? $this->modules['analytics']->track($name, $fields, $sessionId) : '';
    }

    public function identify($userId, $sessionId = null)
    {
        return isset($this->modules['analytics']) ? $this->modules['analytics']->identify($userId, $sessionId) : false;
    }

    public function lead(array $fields, $sessionId = null)
    {
        return isset($this->modules['analytics']) ? $this->modules['analytics']->lead($fields, $sessionId) : null;
    }

    // Laravel: times the request and sends what's waiting, from the
    // middleware's terminate() (Laravel doesn't call protect(), so there's no
    // shutdown run as well).
    public function recordAndSend()
    {
        $this->protected = true;
        $this->afterResponse();
        $this->protected = false;
    }

    // Sends what's waiting and syncs rules and switches when due. Runs at
    // shutdown after protect().
    public function afterResponse()
    {
        try {
            $errors = isset($this->modules['errors']) ? $this->modules['errors'] : null;
            $analytics = isset($this->modules['analytics']) ? $this->modules['analytics'] : null;
            $firewall = isset($this->modules['firewall']) ? $this->modules['firewall'] : null;
            $performance = isset($this->modules['performance']) ? $this->modules['performance'] : null;
            $crawlers = isset($this->modules['crawlers']) ? $this->modules['crawlers'] : null;
            $resources = isset($this->modules['resources']) ? $this->modules['resources'] : null;
            $audit = isset($this->modules['audit']) ? $this->modules['audit'] : null;
            $inventory = isset($this->modules['inventory']) && !$this->modules['inventory']->manual() && $this->core->isOn('inventory')
                ? $this->modules['inventory'] : null;
            $posture = isset($this->modules['posture']) && !$this->modules['posture']->manual() && $this->core->isOn('inventory')
                ? $this->modules['posture'] : null;
            // Timed before anything below: what follows happens after the response.
            if ($performance && $this->protected) {
                $performance->recordRequest();
            }
            if ($crawlers && $this->protected) {
                $crawlers->recordRequest($firewall ? $firewall->clientIp() : (isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : ''));
            }
            // Fatal errors are read now, before deciding whether to send.
            if ($errors) {
                $errors->onShutdown();
            }
            $busy = ($errors && $errors->pending()) || ($analytics && $analytics->pending()) || ($audit && $audit->pending()) || $this->core->switchesDue()
                || ($performance && $performance->due()) || ($crawlers && $crawlers->due()) || ($resources && $resources->due()) || ($inventory && $inventory->due()) || ($posture && $posture->due());
            // Closes the connection so everything below happens after the
            // response. LiteSpeed has its own name for it, and Apache's
            // mod_php has neither: there the visitor waits for the send,
            // which is why it is only ever done once a minute.
            if ($busy) {
                if (function_exists('fastcgi_finish_request')) {
                    @fastcgi_finish_request();
                } elseif (function_exists('litespeed_finish_request')) {
                    @litespeed_finish_request();
                }
            }
            $this->core->syncSwitches();
            if ($errors) {
                $errors->flush();
            }
            if ($analytics) {
                $analytics->flush();
            }
            if ($audit) {
                $audit->flush();
            }
            if ($performance) {
                $performance->flush();
            }
            if ($crawlers) {
                $crawlers->flush();
            }
            if ($resources) {
                $resources->flush();
            }
            if ($firewall) {
                $firewall->afterResponse();
            }
            // About once a day, after everything else.
            if ($inventory && $inventory->due()) {
                $inventory->run();
            }
            if ($posture && $posture->due()) {
                $posture->run();
            }
        } catch (\Throwable $e) {
            // never break the site
        }
    }
}
