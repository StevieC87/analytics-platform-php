<?php
// Feature flags and maintenance mode: both come with the module switches
// (Core), set in Security → Settings → Server package.
// - Flags: on or off for everyone, a share of users (a hash of "key:user",
//   the same in the Node and Python packages), or listed user IDs.
// - Maintenance: a "back soon" page (503) for everyone but the allowed
//   addresses and whoever opened the preview link (?site_preview=<code>,
//   remembered for a day in a cookie).

namespace AnalyticsPlatform;

class Flags
{
    const COOKIE = 'site_preview';

    // FNV-1a over "key:user", 0-99.
    public static function bucket($key, $user)
    {
        $hash = 0x811c9dc5;
        $text = $key . ':' . $user;
        for ($i = 0, $n = strlen($text); $i < $n; $i++) {
            $hash ^= ord($text[$i]);
            $hash = ($hash * 0x01000193) & 0xffffffff;
        }
        return $hash % 100;
    }

    public static function evaluate(array $flag, $key, $user)
    {
        if (empty($flag['on'])) {
            return false;
        }
        $id = $user === null ? '' : (string) $user;
        if ($id !== '' && isset($flag['users']) && is_array($flag['users']) && in_array($id, $flag['users'], true)) {
            return true;
        }
        $rollout = isset($flag['rollout']) ? (int) $flag['rollout'] : 100;
        if ($rollout >= 100) {
            return true;
        }
        if ($rollout <= 0 || $id === '') {
            return false;
        }
        return self::bucket($key, $id) < $rollout;
    }

    // Null to let the request through; otherwise the page to send.
    public static function maintenancePage(array $m, $ip)
    {
        if (empty($m['on'])) {
            return null;
        }
        $key = Firewall::ipKey($ip);
        if ($key !== null && !empty($m['allow']) && Firewall::inList(Firewall::compileList($m['allow']), $key)) {
            return null;
        }
        $code = isset($m['bypass']) ? (string) $m['bypass'] : '';
        if ($code !== '') {
            if (isset($_GET[self::COOKIE]) && hash_equals($code, (string) $_GET[self::COOKIE])) {
                if (!headers_sent()) {
                    setcookie(self::COOKIE, $code, array('expires' => time() + 86400, 'path' => '/', 'httponly' => true, 'samesite' => 'Lax'));
                }
                return null;
            }
            if (isset($_COOKIE[self::COOKIE]) && hash_equals($code, (string) $_COOKIE[self::COOKIE])) {
                return null;
            }
        }
        $message = isset($m['message']) && $m['message'] !== '' ? $m['message'] : "We're doing some maintenance. Please check back in a few minutes.";
        return '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            . '<title>Back soon</title><style>body{margin:0;min-height:100vh;display:grid;place-items:center;font:16px/1.5 system-ui,sans-serif;'
            . 'background:#f8fafc;color:#0f172a}main{max-width:32rem;padding:2rem;text-align:center}h1{font-size:1.6rem;margin:0 0 .5rem}'
            . 'p{color:#475569;margin:0}@media(prefers-color-scheme:dark){body{background:#0f172a;color:#e2e8f0}p{color:#94a3b8}}</style></head>'
            . '<body><main><h1>Back soon</h1><p>' . htmlspecialchars($message, ENT_QUOTES, 'UTF-8') . '</p></main></body></html>';
    }
}
