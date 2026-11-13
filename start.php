<?php
// The one-line setup for any PHP site. Either point PHP at it (php.ini,
// .user.ini, or php_value in .htaccess), so it runs before every script:
//
//   auto_prepend_file = /path/to/your/site/vendor/analytics-platform/platform/start.php
//
// or make it the first line of the script every request goes through:
//
//   require __DIR__ . '/vendor/analytics-platform/platform/start.php';
//
// It reads ANALYTICS_SITE_ID, ANALYTICS_SITE_SECRET and ANALYTICS_ENDPOINT
// from the server's environment, or else from the .env in your project's
// folder (the one holding vendor/), only its ANALYTICS_* lines. It never
// writes them into the environment. Then the firewall, errors and the rest
// run on this request, before your code. analytics_platform() is the
// platform, for track(), captureException() and the rest.
//
// Only the package's own classes are loaded here, not your app's Composer
// autoloader, so nothing of your app runs before your app does. Including it
// twice does nothing the second time. On the command line (cron, artisan,
// composer) nothing runs until you call analytics_platform().

if (!function_exists('analytics_platform')) {
    // The package's classes, wherever it sits: under vendor/ or on its own.
    spl_autoload_register(function ($class) {
        if (strncmp($class, 'AnalyticsPlatform\\', 18) !== 0) {
            return;
        }
        $file = __DIR__ . '/src/' . str_replace('\\', '/', substr($class, 18)) . '.php';
        if (is_file($file)) {
            require $file;
        }
    });

    // The platform for this request, made once.
    function analytics_platform()
    {
        static $platform = null;
        if ($platform !== null) {
            return $platform;
        }
        // The project's folder: the one holding vendor/ when the package is
        // installed there; otherwise the server's environment only.
        $vendor = dirname(__DIR__, 2);
        $dir = basename(dirname(__DIR__)) === 'analytics-platform' && basename($vendor) === 'vendor' ? dirname($vendor) : null;
        // Its .env's ANALYTICS_* lines, as name => value. Not a full .env
        // reader: no variables inside values, and every other line is left alone.
        $file = array();
        $text = $dir !== null && is_file($dir . '/.env') ? @file_get_contents($dir . '/.env') : false;
        foreach (is_string($text) ? preg_split('/\r\n|\r|\n/', $text) : array() as $line) {
            if (!preg_match('/^\s*(?:export\s+)?(ANALYTICS_[A-Z0-9_]+)\s*=\s*(.*)$/', $line, $m)) {
                continue;
            }
            $value = trim($m[2]);
            $quote = $value === '' ? '' : $value[0];
            if (($quote === '"' || $quote === "'") && ($end = strpos($value, $quote, 1)) !== false) {
                $value = substr($value, 1, $end - 1);
            } else {
                $value = trim(preg_replace('/\s+#.*$/', '', $value));
            }
            $file[$m[1]] = $value;
        }
        $platform = new AnalyticsPlatform\Platform(AnalyticsPlatform\Platform::withEnvironment(array(), $file));
        return $platform;
    }

    if (PHP_SAPI !== 'cli') {
        analytics_platform()->protect();
    }
}
