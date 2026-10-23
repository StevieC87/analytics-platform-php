<?php
// Request rules (virtual patching; protocol in sdk/protocols/firewall.md):
// the firewall has always matched addresses, these match the request — its
// method, path, query string and user agent — so an attack is turned away
// before the vulnerable code runs. They arrive with the other rules and are
// compiled once per fetch into plain arrays (the Firewall keeps its rules in a
// PHP file, so nothing here may be an object).
//
// The matching is the same in every package: the shared cases are in
// sdk/protocols/request-rules-cases.json, and this class is run against them
// by test/RequestRulesTest.php.

namespace AnalyticsPlatform;

class RequestRules
{
    const MAX_RULES = 200;
    // How much of each part a rule may look at. Patterns come from our rules,
    // but the text comes from whoever is asking, and PCRE can't be timed out
    // here: a bounded slice keeps a bad pattern from being a hung request.
    const MAX_TEXT = 2000;
    const MAX_REGEX = 200;
    // A delimiter a URL pattern can't hold, so a pattern never has to be escaped.
    const DELIM = "\x01";
    private static $sections = array('path', 'query', 'ua');

    // The rules as they will be matched, or an empty array when there are none.
    public static function compile($data)
    {
        $given = isset($data['rules']) && is_array($data['rules']) ? array_slice($data['rules'], 0, self::MAX_RULES) : array();
        $rules = array();
        foreach ($given as $rule) {
            if (!is_array($rule) || empty($rule['id']) || !is_string($rule['id'])) {
                continue;
            }
            // We are called before the body is read, so a rule that needs the
            // body is skipped whole rather than matched on the rest of it.
            if (isset($rule['body'])) {
                continue;
            }
            $compiled = array(
                'id' => $rule['id'],
                'action' => isset($rule['action']) && $rule['action'] === 'block' ? 'block' : 'monitor',
                'ban' => isset($rule['ban']) && (int) $rule['ban'] > 0 ? (int) $rule['ban'] : 0,
                'methods' => array(),
            );
            if (isset($rule['methods']) && is_array($rule['methods'])) {
                foreach ($rule['methods'] as $method) {
                    if (is_string($method) && preg_match('/^[A-Za-z]{1,10}$/', $method)) {
                        $compiled['methods'][] = strtoupper($method);
                    }
                }
            }
            $sections = 0;
            foreach (self::$sections as $name) {
                $section = self::section(isset($rule[$name]) ? $rule[$name] : null);
                if ($section !== null) {
                    $compiled[$name] = $section;
                    $sections++;
                }
            }
            // A rule with nothing to match would match everything.
            if (!$sections) {
                continue;
            }
            $rules[] = $compiled;
        }
        return $rules;
    }

    // A pattern can only come from us, but a careless one would be matched
    // against text an attacker chooses, in this very request, and PCRE can't be
    // timed out here. So the client checks the shape itself instead of trusting
    // what it was handed: a quantifier on a group that itself repeats
    // ("(a+)+") takes exponential time on input that nearly matches.
    // Backreferences and lookbehind are refused for the same reason.
    public static function safePattern($pattern)
    {
        if (!is_string($pattern) || $pattern === '' || strlen($pattern) > self::MAX_REGEX) {
            return false;
        }
        if (preg_match('/\\\\[1-9]/', $pattern) || strpos($pattern, '(?<') !== false) {
            return false;
        }
        $open = array();
        for ($i = 0; $i < strlen($pattern); $i++) {
            $char = $pattern[$i];
            if ($char === '\\') {
                $i++;
                continue;
            }
            if ($char === '[') {
                // A character class: quantifiers inside it are literals.
                while ($i < strlen($pattern) && $pattern[$i] !== ']') {
                    $i += $pattern[$i] === '\\' ? 2 : 1;
                }
                continue;
            }
            if ($char === '(') {
                $open[] = $i;
            } elseif ($char === ')') {
                if (!$open) {
                    return false;
                }
                $start = array_pop($open);
                $next = isset($pattern[$i + 1]) ? $pattern[$i + 1] : '';
                if ($next === '*' || $next === '+' || $next === '{') {
                    $inside = substr($pattern, $start + 1, $i - $start - 1);
                    if (preg_match('/(^|[^\\\\])[*+]/', $inside) || preg_match('/(^|[^\\\\])\{[0-9]/', $inside)) {
                        return false;
                    }
                }
            }
        }
        return !$open;
    }

    private static function section($section)
    {
        if (!is_array($section)) {
            return null;
        }
        $out = array();
        foreach (array('exact', 'prefix', 'suffix', 'contains') as $matcher) {
            if (!isset($section[$matcher]) || !is_array($section[$matcher])) {
                continue;
            }
            $list = array();
            foreach ($section[$matcher] as $entry) {
                if (is_string($entry) && ($matcher === 'exact' || $entry !== '')) {
                    $list[] = strtolower($entry);
                }
            }
            if ($list) {
                $out[$matcher] = $list;
            }
        }
        if (isset($section['regex']) && self::safePattern($section['regex'])) {
            $pattern = self::DELIM . $section['regex'] . self::DELIM . 'i';
            // A pattern we can't compile is dropped; the rule's other parts stay.
            if (@preg_match($pattern, '') !== false) {
                $out['regex'] = $section['regex'];
            }
        }
        return $out ? $out : null;
    }

    // One pass only, as the protocol says: enough for %2e%2e, and no risk of
    // decoding a visitor's own text into something that looks like an attack.
    private static function decodeOnce($text)
    {
        if (strpos($text, '%') === false && strpos($text, '+') === false) {
            return $text;
        }
        $decoded = @rawurldecode(str_replace('+', ' ', $text));
        return is_string($decoded) ? $decoded : $text;
    }

    private static function normalizePath($path)
    {
        return preg_replace('~/{2,}~', '/', str_replace('\\', '/', strtolower($path)));
    }

    private static function hits(array $section, $raw, $decoded)
    {
        $texts = $decoded === $raw ? array($raw) : array($raw, $decoded);
        foreach ($texts as $text) {
            if (isset($section['exact']) && in_array($text, $section['exact'], true)) {
                return true;
            }
            if (isset($section['prefix'])) {
                foreach ($section['prefix'] as $entry) {
                    if (strpos($text, $entry) === 0) {
                        return true;
                    }
                }
            }
            if (isset($section['suffix'])) {
                foreach ($section['suffix'] as $entry) {
                    if ($entry !== '' && substr($text, -strlen($entry)) === $entry) {
                        return true;
                    }
                }
            }
            if (isset($section['contains'])) {
                foreach ($section['contains'] as $entry) {
                    if ($entry !== '' && strpos($text, $entry) !== false) {
                        return true;
                    }
                }
            }
            if (isset($section['regex']) && @preg_match(self::DELIM . $section['regex'] . self::DELIM . 'i', $text) === 1) {
                return true;
            }
        }
        return false;
    }

    // The first rule that matches, or null. $path is the request target as the
    // server received it, query string and all.
    public static function matchRequest(array $rules, $method, $path, $userAgent)
    {
        if (!$rules) {
            return null;
        }
        $target = (string) $path;
        $mark = strpos($target, '?');
        $rawPath = self::normalizePath(substr($mark === false ? $target : substr($target, 0, $mark), 0, self::MAX_TEXT));
        $rawQuery = strtolower(substr($mark === false ? '' : substr($target, $mark + 1), 0, self::MAX_TEXT));
        $ua = strtolower(substr((string) $userAgent, 0, self::MAX_TEXT));
        $decodedPath = self::normalizePath(substr(self::decodeOnce(substr($mark === false ? $target : substr($target, 0, $mark), 0, self::MAX_TEXT)), 0, self::MAX_TEXT));
        $decodedQuery = substr(self::decodeOnce($rawQuery), 0, self::MAX_TEXT);
        $upper = strtoupper((string) $method);
        foreach ($rules as $rule) {
            if ($rule['methods'] && !in_array($upper, $rule['methods'], true)) {
                continue;
            }
            if (isset($rule['path']) && !self::hits($rule['path'], $rawPath, $decodedPath)) {
                continue;
            }
            if (isset($rule['query']) && !self::hits($rule['query'], $rawQuery, $decodedQuery)) {
                continue;
            }
            if (isset($rule['ua']) && !self::hits($rule['ua'], $ua, $ua)) {
                continue;
            }
            return $rule;
        }
        return null;
    }
}
