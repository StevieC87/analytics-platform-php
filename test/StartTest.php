<?php
// The keys from the environment (Platform::withEnvironment) and start.php,
// the one-line setup: the server's environment first, else the project's
// .env (its ANALYTICS_* lines only, never written into the environment);
// options passed in code always win; WordPress is left as it was; start.php
// included twice makes one platform. The Symfony bundle is checked in
// SymfonyBundleTest.php, which needs Symfony.
//
//   php test/StartTest.php

spl_autoload_register(function ($class) {
    if (strncmp($class, 'AnalyticsPlatform\\', 18) === 0) {
        $file = __DIR__ . '/../src/' . str_replace('\\', '/', substr($class, 18)) . '.php';
        if (is_file($file)) {
            require $file;
        }
    }
});

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

$names = array('ANALYTICS_SITE_ID', 'ANALYTICS_SITE_SECRET', 'ANALYTICS_ENDPOINT', 'ANALYTICS_FIREWALL_ENDPOINT', 'ANALYTICS_SERVER_NAME', 'ANALYTICS_TRUST_PROXY');
function clear_env($names)
{
    foreach ($names as $name) {
        putenv($name);
        unset($_ENV[$name], $_SERVER[$name]);
    }
}
$id = str_repeat('a', 24);

// ---- withEnvironment ----
clear_env($names);
putenv("ANALYTICS_SITE_ID=$id");
$_SERVER['ANALYTICS_SITE_SECRET'] = 's3cret';
$_ENV['ANALYTICS_FIREWALL_ENDPOINT'] = 'https://old-name.example';
putenv('ANALYTICS_SERVER_NAME=web');
putenv('ANALYTICS_TRUST_PROXY=cloudflare');
$o = Platform::withEnvironment(array());
check('site id from getenv()', $o['site_id'] === $id);
check('secret from $_SERVER', $o['secret'] === 's3cret');
check('the endpoint under its Laravel/Symfony name too', $o['endpoint'] === 'https://old-name.example');
check('server name', $o['server_name'] === 'web');
check('trust proxy: cloudflare', $o['trust_proxy'] === 'cloudflare');
putenv('ANALYTICS_ENDPOINT=https://new-name.example');
check('ANALYTICS_ENDPOINT before the old name', Platform::withEnvironment(array())['endpoint'] === 'https://new-name.example');
putenv('ANALYTICS_TRUST_PROXY=2');
check('trust proxy: a number of proxies', Platform::withEnvironment(array())['trust_proxy'] === 2);
putenv('ANALYTICS_TRUST_PROXY=nonsense');
check('trust proxy: anything else is left out', !array_key_exists('trust_proxy', Platform::withEnvironment(array())));

$given = Platform::withEnvironment(array('site_id' => str_repeat('b', 24), 'secret' => 'mine', 'endpoint' => 'https://mine.example', 'trust_proxy' => 0));
check('options passed in code win', $given['site_id'] === str_repeat('b', 24) && $given['secret'] === 'mine' && $given['endpoint'] === 'https://mine.example');
check('a trust_proxy given (even 0) is kept', $given['trust_proxy'] === 0);
$empty = Platform::withEnvironment(array('site_id' => null, 'secret' => '', 'endpoint' => null));
check('null or empty (an unset Laravel env()) is filled', $empty['site_id'] === $id && $empty['secret'] === 's3cret' && $empty['endpoint'] === 'https://new-name.example');
check('false (getenv() of a variable it can\'t see) is filled too', Platform::withEnvironment(array('secret' => false))['secret'] === 's3cret');
$wp = Platform::withEnvironment(array('platform' => 'wordpress', 'site_id' => '', 'secret' => ''));
check('WordPress: nothing read from the environment', $wp === array('platform' => 'wordpress', 'site_id' => '', 'secret' => ''));
clear_env($names);
$file = Platform::withEnvironment(array(), array('ANALYTICS_SITE_ID' => $id, 'ANALYTICS_SITE_SECRET' => 'from-file', 'ANALYTICS_ENDPOINT' => 'https://file.example'));
check('the file fills what the environment leaves out', $file['secret'] === 'from-file' && $file['endpoint'] === 'https://file.example');
putenv('ANALYTICS_SITE_SECRET=from-server');
check('the server environment wins over the file', Platform::withEnvironment(array(), array('ANALYTICS_SITE_SECRET' => 'from-file'))['secret'] === 'from-server');
clear_env($names);
check('a Platform with no options at all, from the environment', (function () use ($id) {
    putenv("ANALYTICS_SITE_ID=$id");
    putenv('ANALYTICS_SITE_SECRET=s');
    putenv('ANALYTICS_ENDPOINT=http://127.0.0.1:9');
    $platform = new Platform(array('storage' => sys_get_temp_dir() . '/analytics-start-test-' . getmypid(), 'inventory' => false, 'resources' => false));
    return $platform->configured();
})());
clear_env($names);

// ---- start.php, laid out as Composer installs it ----
$project = sys_get_temp_dir() . '/analytics-start-project-' . getmypid();
$package = $project . '/vendor/analytics-platform/platform';
@mkdir($package . '/src', 0775, true);
copy(__DIR__ . '/../start.php', $package . '/start.php');
foreach (glob(__DIR__ . '/../src/*.php') as $src) {
    copy($src, $package . '/src/' . basename($src));
}
file_put_contents($project . '/.env', implode("\n", array(
    'APP_SECRET=left-alone',
    "ANALYTICS_SITE_ID=\"$id\"",
    "export ANALYTICS_SITE_SECRET='from-dotenv' # the comment is not part of it",
    'ANALYTICS_ENDPOINT=http://127.0.0.1:9 # nor is this one',
)));
$script = $project . '/run.php';
file_put_contents($script, '<?php
require ' . var_export($package . '/start.php', true) . ';
require ' . var_export($package . '/start.php', true) . ';
$a = analytics_platform();
$secret = $a->core()->opt("secret");
echo json_encode(array(
    "configured" => $a->configured(),
    "secret" => $secret,
    "endpoint" => $a->core()->opt("endpoint"),
    "once" => $a === analytics_platform(),
    "env_untouched" => getenv("ANALYTICS_SITE_SECRET") === false && !isset($_ENV["ANALYTICS_SITE_SECRET"]) && !isset($_SERVER["ANALYTICS_SITE_SECRET"]),
    "app_secret_untouched" => getenv("APP_SECRET") === false,
));
');
$env = array('PATH' => getenv('PATH'));
$proc = proc_open(array(PHP_BINARY, '-d', 'variables_order=EGPCS', $script), array(1 => array('pipe', 'w'), 2 => array('pipe', 'w')), $pipes, $project, $env);
$out = stream_get_contents($pipes[1]);
$err = stream_get_contents($pipes[2]);
proc_close($proc);
$seen = json_decode($out, true);
check('start.php ran: ' . $out . $err, is_array($seen));
if (is_array($seen)) {
    check('start.php: configured from the project .env', $seen['configured'] === true);
    check('start.php: quotes and trailing comments taken off', $seen['secret'] === 'from-dotenv' && $seen['endpoint'] === 'http://127.0.0.1:9');
    check('start.php: included twice, one platform', $seen['once'] === true);
    check('start.php: nothing written into the environment', $seen['env_untouched'] === true && $seen['app_secret_untouched'] === true);
}
// The server's environment beats the file.
$proc = proc_open(array(PHP_BINARY, $script), array(1 => array('pipe', 'w'), 2 => array('pipe', 'w')), $pipes, $project, $env + array('ANALYTICS_SITE_SECRET' => 'from-server'));
$seen = json_decode(stream_get_contents($pipes[1]), true);
proc_close($proc);
check('start.php: the server environment wins', is_array($seen) && $seen['secret'] === 'from-server');

$rm = function ($dir) use (&$rm) {
    foreach (array_diff(scandir($dir) ?: array(), array('.', '..')) as $entry) {
        is_dir("$dir/$entry") ? $rm("$dir/$entry") : unlink("$dir/$entry");
    }
    rmdir($dir);
};
$rm($project);
foreach (glob(sys_get_temp_dir() . '/analytics-start-test-' . getmypid() . '*') ?: array() as $dir) {
    $rm($dir);
}

echo ($failed ? "FAILED" : "OK") . ": $checked checks, $failed failed\n";
exit($failed ? 1 : 0);
