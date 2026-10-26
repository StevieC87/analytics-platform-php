<?php
// What every module of the PHP package shares: the site's credentials, the
// storage directory, sending to the collector, and the dashboard's module
// switches (Security → Server package, GET /events/platform/config).
//
// PHP keeps nothing between requests, so the switches are kept in the
// storage directory as a PHP file (OPcache holds it in memory) and fetched
// after the response, about once a minute, by one request at a time. Until
// they arrive, or when they can't be fetched, every loaded module stays on.

namespace AnalyticsPlatform;

class Core
{
    const VERSION = '0.3.0';
    const TIMEOUT = 4;
    const MIN_SYNC = 30;
    const RETRY = 60;
    // Batches the collector couldn't take, kept to be sent again: at most this
    // many bytes of them, and this many resent per run.
    const RETRY_MAX = 2000000;
    const RESEND = 20;

    public $options;
    // Appended to the User-Agent, e.g. " (no-rate)" when the firewall can't count.
    public $features = '';
    private $dir;
    private $legacyDir = '';
    private $switches = null;
    private $loaded = array();

    // Options: site_id, secret, endpoint (required); storage (a writable
    // directory; default the system temp directory); platform (for the
    // dashboard, default 'php').
    public function __construct(array $options)
    {
        $this->options = $options + array(
            'storage' => sys_get_temp_dir() . '/analytics-firewall',
            'platform' => 'php',
        );
        $id = preg_replace('/[^a-f0-9]/i', '', (string) $this->opt('site_id'));
        // The folder may not be named after the site id alone. On WordPress the
        // storage lives under wp-content, which the web server serves, and the
        // site id is a data-siteid attribute in every page of the site — so a
        // folder named after it could simply be asked for, and events.jsonl
        // (visitor addresses and what they requested), crawlers.jsonl and
        // files.json (every path on the site) handed out. The .htaccess written
        // next to them only covers Apache and LiteSpeed; nginx ignores it. The
        // secret never leaves the server, so a name derived from it can't be
        // guessed from outside.
        $base = rtrim($this->options['storage'], '/\\');
        $this->dir = $base . '/' . ($id === '' ? '' : $id . '-' . substr(hash('sha256', $id . '|' . (string) $this->opt('secret')), 0, 16));
        // Where it used to be, when the name was guessable.
        $this->legacyDir = $id === '' ? '' : $base . '/' . $id;
    }

    public function opt($key)
    {
        return isset($this->options[$key]) ? $this->options[$key] : null;
    }

    public function configured()
    {
        return preg_match('/^[a-f0-9]{24}$/i', (string) $this->opt('site_id')) && $this->opt('secret') && $this->opt('endpoint');
    }

    public function dir()
    {
        return $this->dir;
    }

    public function ensureDir()
    {
        if (is_dir($this->dir)) {
            return true;
        }
        if (!@mkdir($this->dir, 0775, true) && !is_dir($this->dir)) {
            return false;
        }
        // Only on the one request that creates the new folder, so this costs
        // nothing afterwards.
        $this->removeLegacy();
        @file_put_contents($this->dir . '/index.html', '');
        @file_put_contents($this->dir . '/.htaccess', "<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\nDeny from all\n</IfModule>\n");
        return true;
    }

    // The folder from before the name was unguessable held the same events,
    // crawler hits and file list, at a web address anyone could work out, so it
    // is emptied rather than left behind. It only ever holds flat files.
    private function removeLegacy()
    {
        if ($this->legacyDir === '' || $this->legacyDir === $this->dir || !is_dir($this->legacyDir)) {
            return;
        }
        foreach (glob($this->legacyDir . '/*') ?: array() as $path) {
            if (is_file($path)) {
                @unlink($path);
            }
        }
        @rmdir($this->legacyDir);
    }

    // Writes a value as a PHP file, atomically, so OPcache can keep it.
    public function writePhp($name, $value)
    {
        $file = $this->dir . '/' . $name;
        $tmp = $file . '.' . getmypid() . '.tmp';
        $php = "<?php\n// Written by the analytics package; rewritten on every sync.\nreturn " . var_export($value, true) . ";\n";
        if (@file_put_contents($tmp, $php, LOCK_EX) === false || !@rename($tmp, $file)) {
            @unlink($tmp);
            return false;
        }
        if (function_exists('opcache_invalidate')) {
            @opcache_invalidate($file, true);
        }
        return true;
    }

    public function readPhp($name)
    {
        $file = $this->dir . '/' . $name;
        return is_file($file) ? @include $file : null;
    }

    // ---- Module switches ----------------------------------------------------

    public function setLoaded(array $names)
    {
        $this->loaded = $names;
    }

    private function switches()
    {
        if ($this->switches === null) {
            $saved = $this->readPhp('switches.php');
            $this->switches = is_array($saved) ? $saved : array('fetched' => 0, 'sync' => self::RETRY, 'etag' => '', 'modules' => array());
        }
        return $this->switches;
    }

    // False only when the dashboard turned the module off.
    public function isOn($name)
    {
        $switches = $this->switches();
        return !(isset($switches['modules'][$name]) && $switches['modules'][$name] === false);
    }

    public function flags()
    {
        $switches = $this->switches();
        return $this->isOn('flags') && isset($switches['flags']) && is_array($switches['flags']) ? $switches['flags'] : array();
    }

    public function maintenance()
    {
        $switches = $this->switches();
        return $this->isOn('maintenance') && isset($switches['maintenance']) && is_array($switches['maintenance']) ? $switches['maintenance'] : array('on' => false);
    }

    // The security headers picked on the dashboard, when the module is on.
    public function securityHeaders()
    {
        $switches = $this->switches();
        return $this->isOn('headers') && isset($switches['headers']) && is_array($switches['headers']) ? $switches['headers'] : array();
    }

    public function switchesDue()
    {
        $switches = $this->switches();
        return time() >= $switches['fetched'] + $switches['sync'];
    }

    // Fetches the switches when due, one request at a time.
    public function syncSwitches($force = false)
    {
        if (!$this->configured() || !$this->ensureDir() || (!$force && !$this->switchesDue())) {
            return;
        }
        $lock = @fopen($this->dir . '/switches.lock', 'c');
        if (!$lock || !flock($lock, LOCK_EX | LOCK_NB)) {
            return;
        }
        $switches = $this->switches();
        $headers = array('X-Platform-Modules: ' . implode(',', $this->loaded));
        if ($switches['etag'] !== '' && !$force) {
            $headers[] = 'If-None-Match: ' . $switches['etag'];
        }
        $res = $this->http('GET', '/events/platform/config?site_id=' . rawurlencode($this->opt('site_id')), null, $headers, 'bearer');
        $switches['fetched'] = time();
        // Unchanged (304): the interval the dashboard last gave still holds.
        if ($res['status'] !== 304) {
            $switches['sync'] = self::RETRY;
        }
        if ($res['status'] === 200) {
            $data = json_decode($res['body'], true);
            if (is_array($data) && isset($data['v']) && $data['v'] === 1 && isset($data['modules']) && is_array($data['modules'])) {
                $switches['modules'] = $data['modules'];
                $switches['flags'] = isset($data['flags']) && is_array($data['flags']) ? $data['flags'] : array();
                $switches['maintenance'] = isset($data['maintenance']) && is_array($data['maintenance']) ? $data['maintenance'] : array('on' => false);
                // Only well-formed headers (no line breaks can get through).
                $switches['headers'] = array();
                foreach (isset($data['headers']) && is_array($data['headers']) ? $data['headers'] : array() as $pair) {
                    if (is_array($pair) && count($pair) === 2 && is_string($pair[0]) && is_string($pair[1])
                        && preg_match('/^[A-Za-z][A-Za-z0-9-]{0,63}$/', $pair[0]) && !preg_match('/[\r\n]/', $pair[1]) && strlen($pair[1]) <= 4000) {
                        $switches['headers'][] = array($pair[0], $pair[1]);
                    }
                }
                $switches['etag'] = isset($res['headers']['etag']) ? $res['headers']['etag'] : '';
                $switches['sync'] = max(self::MIN_SYNC, (int) (isset($data['sync']) ? $data['sync'] : self::RETRY));
            }
        }
        $this->writePhp('switches.php', $switches);
        $this->switches = $switches;
        flock($lock, LOCK_UN);
        fclose($lock);
    }

    // ---- Spools ---------------------------------------------------------------
    // What a request records for the collector (blocked requests, timings,
    // crawler hits, machine samples) is appended to <name>.jsonl, one line
    // each, and sent later by one request at a time. A batch the collector
    // couldn't take, when trying again may work (unreachable, 429, 5xx), is
    // kept in <name>.retry.jsonl and sent before the next one; a 4xx is
    // dropped, because resending won't make it acceptable.

    // False when the spool is full (more than $max bytes) or can't be written.
    public function append($name, array $row, $max)
    {
        $file = $this->dir . '/' . $name . '.jsonl';
        clearstatcache(true, $file);
        if (is_file($file) && filesize($file) > $max) {
            return false;
        }
        return @file_put_contents($file, json_encode($row, JSON_INVALID_UTF8_SUBSTITUTE) . "\n", FILE_APPEND | LOCK_EX) !== false;
    }

    // Whether anything is waiting to be sent, new or to be resent.
    public function waiting($name)
    {
        clearstatcache();
        return is_file($this->dir . '/' . $name . '.jsonl') || is_file($this->dir . '/' . $name . '.retry.jsonl');
    }

    // Whether the last send was at least $every seconds ago.
    public function sendDue($name, $every)
    {
        $mark = $this->dir . '/' . $name . '.lock';
        clearstatcache(true, $mark);
        return !is_file($mark) || filemtime($mark) <= time() - $every;
    }

    // Takes everything waiting in the spool and hands its rows to $send,
    // which sends them with post(). At most every $every seconds unless
    // $force, and one request at a time.
    public function drain($name, $every, $force, callable $send)
    {
        if (!$this->waiting($name) || (!$force && !$this->sendDue($name, $every))) {
            return;
        }
        $lock = @fopen($this->dir . '/' . $name . '.lock', 'c');
        if (!$lock || !flock($lock, LOCK_EX | LOCK_NB)) {
            return;
        }
        @touch($this->dir . '/' . $name . '.lock');
        try {
            $this->resend($name);
            $rows = array();
            foreach ($this->take($this->dir . '/' . $name . '.jsonl') as $line) {
                $row = json_decode($line, true);
                if (is_array($row)) {
                    $rows[] = $row;
                }
            }
            if ($rows) {
                $send($rows);
            }
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    // POSTs one batch for the spool $name, keeping it to resend when the
    // collector couldn't take it. The credentials are added when it is sent,
    // so they are never written down with it.
    public function post($name, $path, array $body, $auth = 'body')
    {
        $res = $this->http('POST', $path, $body, array(), $auth);
        if ($res['status'] === 0 || $res['status'] === 429 || $res['status'] >= 500) {
            $this->append($name . '.retry', array('path' => $path, 'auth' => $auth, 'body' => $body), self::RETRY_MAX);
        }
        return $res;
    }

    // Sends what earlier runs couldn't, oldest first. Once one fails the
    // collector is still away, so the rest go back unsent.
    private function resend($name)
    {
        $file = $this->dir . '/' . $name . '.retry.jsonl';
        $lines = $this->take($file);
        foreach ($lines as $i => $line) {
            $batch = json_decode($line, true);
            if (!is_array($batch) || !isset($batch['path'], $batch['body']) || !is_array($batch['body'])
                || strpos((string) $batch['path'], '/events/') !== 0) {
                continue;
            }
            $auth = isset($batch['auth']) && $batch['auth'] === 'bearer' ? 'bearer' : 'body';
            $res = $i < self::RESEND ? $this->http('POST', $batch['path'], $batch['body'], array(), $auth) : array('status' => 0);
            if ($res['status'] === 0 || $res['status'] === 429 || $res['status'] >= 500) {
                $rest = array_slice($lines, $i);
                @file_put_contents($file, implode("\n", $rest) . "\n", FILE_APPEND | LOCK_EX);
                return;
            }
        }
    }

    // The lines of a spool file, which is removed: renamed first, so lines
    // other requests append meanwhile start a new file rather than being lost.
    private function take($file)
    {
        $sending = $file . '.' . getmypid() . '.sending';
        clearstatcache(true, $file);
        if (!is_file($file) || !@rename($file, $sending)) {
            return array();
        }
        $lines = file($sending, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: array();
        @unlink($sending);
        return $lines;
    }

    // ---- HTTP ---------------------------------------------------------------

    // auth 'bearer' sends the secret as a header (firewall, switches); 'body'
    // adds site_id and sitesecret to the JSON body (the event endpoints).
    public function http($method, $path, $body = null, array $headers = array(), $auth = 'bearer')
    {
        $result = array('status' => 0, 'body' => '', 'headers' => array());
        if (!$this->configured()) {
            return $result;
        }
        if ($body !== null) {
            if ($auth === 'body') {
                $body = array('site_id' => (string) $this->opt('site_id'), 'sitesecret' => (string) $this->opt('secret')) + $body;
            }
            // A name that isn't UTF-8 (a file, a path) has its bad bytes
            // replaced rather than failing the encoding and losing the whole body.
            $body = json_encode($body, JSON_INVALID_UTF8_SUBSTITUTE);
            $headers[] = 'Content-Type: application/json';
        }
        if ($auth === 'bearer') {
            $headers[] = 'Authorization: Bearer ' . $this->opt('secret');
        }
        $headers[] = 'User-Agent: analytics-platform-' . $this->options['platform'] . '/' . self::VERSION . $this->features;
        $url = rtrim($this->opt('endpoint'), '/') . $path;
        if (function_exists('curl_init')) {
            $ch = curl_init($url);
            curl_setopt_array($ch, array(
                CURLOPT_CUSTOMREQUEST => $method,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT => self::TIMEOUT,
                CURLOPT_CONNECTTIMEOUT => self::TIMEOUT,
                CURLOPT_HTTPHEADER => $headers,
                CURLOPT_HEADERFUNCTION => function ($ch, $line) use (&$result) {
                    $parts = explode(':', $line, 2);
                    if (count($parts) === 2) {
                        $result['headers'][strtolower(trim($parts[0]))] = trim($parts[1]);
                    }
                    return strlen($line);
                },
            ));
            if ($body !== null) {
                curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
            }
            $response = curl_exec($ch);
            $result['status'] = $response === false ? 0 : (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $result['body'] = $response === false ? '' : $response;
            curl_close($ch);
            return $result;
        }
        $context = stream_context_create(array('http' => array(
            'method' => $method,
            'header' => implode("\r\n", $headers),
            'content' => $body === null ? '' : $body,
            'timeout' => self::TIMEOUT,
            'ignore_errors' => true,
        )));
        $response = @file_get_contents($url, false, $context);
        // PHP 8.4 added http_get_last_response_headers(); 8.5 deprecated the
        // $http_response_header variable this fell back on. The old name is
        // reached through get_defined_vars() so that naming it cannot raise
        // the deprecation on 8.5, while 7.4 still gets its headers. Either way
        // the first line is the status line, which the loop below relies on.
        if (function_exists('http_get_last_response_headers')) {
            $lines = http_get_last_response_headers();
            $lines = $lines === null ? array() : $lines;
        } else {
            $scope = get_defined_vars();
            $lines = isset($scope['http_response_header']) ? $scope['http_response_header'] : array();
        }
        foreach ($lines as $i => $line) {
            if ($i === 0 && preg_match('#^HTTP/\S+\s+(\d{3})#', $line, $m)) {
                $result['status'] = (int) $m[1];
            }
            $parts = explode(':', $line, 2);
            if ($i > 0 && count($parts) === 2) {
                $result['headers'][strtolower(trim($parts[0]))] = trim($parts[1]);
            }
        }
        $result['body'] = $response === false ? '' : $response;
        return $result;
    }
}
