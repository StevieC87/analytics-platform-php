<?php
// Where the package keeps its files, and that the folder's name cannot be
// worked out from outside. On WordPress the storage sits under wp-content,
// which the web server serves, and the site id is an attribute in every page
// of the site — so a folder named after the id alone would hand out
// events.jsonl (visitor addresses and what they asked for), crawlers.jsonl
// and files.json to anyone who looked.
//
//   php test/CoreTest.php
// (No dependencies: the package has none, so this is plain PHP, not PHPUnit.)

require __DIR__ . '/../src/Core.php';

use AnalyticsPlatform\Core;

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

$id = 'a1b2c3d4e5f6a1b2c3d4e5f6';
$store = sys_get_temp_dir() . '/analytics-core-test-' . getmypid();
$options = array('site_id' => $id, 'secret' => 'the-site-secret', 'endpoint' => 'https://collector.example', 'storage' => $store);

// The folder as it used to be named, holding what used to be downloadable.
@mkdir($store . '/' . $id, 0775, true);
file_put_contents($store . '/' . $id . '/events.jsonl', "{\"ip\":\"203.0.113.9\",\"path\":\"/.env\"}\n");

$core = new Core($options);
check('the folder is not named after the site id', basename($core->dir()) !== $id);
check('the site id is still in the name, for an operator reading it', strpos(basename($core->dir()), $id) === 0);
check('the secret decides the rest of the name', (new Core(array('secret' => 'another-secret') + $options))->dir() !== $core->dir());

check('the folder is created', $core->ensureDir() && is_dir($core->dir()));
check('what the guessable folder held is deleted', !file_exists($store . '/' . $id . '/events.jsonl'));
check('the guessable folder itself is gone', !is_dir($store . '/' . $id));
check('the folder is kept from being served where .htaccess is read', is_file($core->dir() . '/.htaccess'));
check('creating it again is harmless', $core->ensureDir());

$core->writePhp('switches.php', array('fetched' => 7, 'modules' => array('firewall' => false)));
$back = $core->readPhp('switches.php');
check('a value survives being written and read', is_array($back) && $back['fetched'] === 7 && $back['modules']['firewall'] === false);

// Whatever the site id says, the path stays inside the storage folder.
$escape = new Core(array('site_id' => '../../../../etc/passwd') + $options);
check('a site id cannot climb out of the storage folder', strpos($escape->dir(), '..') === false);

// What is kept is this user's alone: the folder 0700, its files 0600
// (switches.php holds maintenance mode's bypass code).
if (DIRECTORY_SEPARATOR === '/') {
    check('the folder is closed to other users', (fileperms($core->dir()) & 0777) === 0700);
    check('and what is written in it', (fileperms($core->dir() . '/switches.php') & 0777) === 0600);
    $core->append('mode', array('n' => 1), 1000);
    clearstatcache();
    check('a spool too', (fileperms($core->dir() . '/mode.jsonl') & 0777) === 0600);
    @unlink($core->dir() . '/mode.jsonl');
    // A file others could have written is never run.
    chmod($core->dir() . '/switches.php', 0666);
    check('a file others can write to is not included', (new Core($options))->readPhp('switches.php') === null);
    chmod($core->dir() . '/switches.php', 0600);
    @symlink($core->dir() . '/switches.php', $core->dir() . '/linked.php');
    check('nor a link', (new Core($options))->readPhp('linked.php') === null);
    @unlink($core->dir() . '/linked.php');
    // A folder an older version made 0775 is closed on first use.
    chmod($core->dir(), 0775);
    check('an open folder of ours is closed', (new Core($options))->readPhp('switches.php') !== null && (fileperms($core->dir()) & 0777) === 0700);
}

// Without the secret the name could be worked out from the site id, so
// there is no folder at all until the package is configured, and nothing
// is spooled.
$bare = new Core(array('secret' => '') + $options);
check('no secret, no folder', $bare->dir() === '' && !$bare->ensureDir() && $bare->readPhp('switches.php') === null);
$bare->post('test', '/events/test', array('rows' => array(1)));
check('and nothing is spooled', !$bare->append('test', array('n' => 1), 1000) && !$bare->waiting('test')
    && glob($store . '/*.jsonl') === array());
// A folder named from an empty secret (older versions spooled into one) is
// emptied once the secret is set, as the guessable one is.
$other = 'b1b2c3d4e5f6a1b2c3d4e5f6';
$empty = $store . '/' . $other . '-' . substr(hash('sha256', $other . '|'), 0, 16);
@mkdir($empty, 0700, true);
file_put_contents($empty . '/analytics.retry.jsonl', "{}\n");
// And the old guessable one may be a link another user made to somewhere of
// the site's: nothing it points at is touched.
$victim = $store . '/victim';
@mkdir($victim, 0700, true);
file_put_contents($victim . '/index.php', '<?php');
@symlink($victim, $store . '/' . $other);
$named = new Core(array('site_id' => $other) + $options);
check('a site whose old folders are odd still gets its own', $named->ensureDir());
check('the folder named from an empty secret is emptied', !file_exists($empty . '/analytics.retry.jsonl') && !is_dir($empty));
check('a link where the old folder was is not followed', is_file($victim . '/index.php') && is_link($store . '/' . $other));
@unlink($store . '/' . $other);
@unlink($victim . '/index.php');
@rmdir($victim);
foreach (glob($named->dir() . '/{,.}*', GLOB_BRACE) ?: array() as $path) {
    is_file($path) && @unlink($path);
}
@rmdir($named->dir());

// No storage given: under the system temp folder, in one of this user's
// own, which another user can't have made first or swapped for a link.
if (DIRECTORY_SEPARATOR === '/' && function_exists('posix_geteuid')) {
    $tmp = $store . '-tmp';
    @mkdir($tmp, 0777, true);
    chmod($tmp, 01777);
    $child = function ($code) use ($tmp) {
        $script = $tmp . '/child.php';
        file_put_contents($script, "<?php require " . var_export(__DIR__ . '/../src/Core.php', true) . ";\n" . $code);
        return trim((string) shell_exec('TMPDIR=' . escapeshellarg($tmp) . ' ' . escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($script)));
    };
    $make = '$c = new AnalyticsPlatform\Core(array("site_id" => "' . $id . '", "secret" => "s", "endpoint" => "https://c.example"));';
    $own = $tmp . '/analytics-firewall-' . posix_geteuid();
    check('a new install keeps its files in a folder of its user\'s',
        $child($make . ' echo $c->ensureDir() ? dirname($c->dir()) : "no";') === $own && (fileperms($own) & 0777) === 0700);
    // The shared name, made by someone else first, is not used.
    $rm = function ($dir) use (&$rm) {
        foreach (array_diff(scandir($dir) ?: array(), array('.', '..')) as $name) {
            is_dir($dir . '/' . $name) && !is_link($dir . '/' . $name) ? $rm($dir . '/' . $name) : @unlink($dir . '/' . $name);
        }
        @rmdir($dir);
    };
    $rm($own);
    @mkdir($tmp . '/elsewhere', 0700);
    @symlink($tmp . '/elsewhere', $own);
    check('a link in its place is refused, and nothing is kept', $child($make . ' echo $c->ensureDir() ? "yes" : "no";') === 'no'
        && scandir($tmp . '/elsewhere') === array('.', '..'));
    $rm($tmp);
}

// The collector's answers, scripted: http() is the one way out.
class ScriptedCore extends Core
{
    public $answers = array();
    public $sent = array();

    public function http($method, $path, $body = null, array $headers = array(), $auth = 'bearer')
    {
        $this->sent[] = array($path, $body);
        $status = $this->answers ? array_shift($this->answers) : 200;
        return array('status' => $status, 'body' => '', 'headers' => array());
    }
}

$scripted = new ScriptedCore($options);
$scripted->ensureDir();
$send = function (array $rows) use ($scripted) {
    $scripted->post('test', '/events/test', array('rows' => $rows));
};
$scripted->append('test', array('n' => 1), 1000000);
$scripted->answers = array(503);
$scripted->drain('test', 60, true, $send);
check('a batch the collector could not take is kept', is_file($scripted->dir() . '/test.retry.jsonl') && !is_file($scripted->dir() . '/test.jsonl'));
check('and nothing is written but the rows: no credentials', strpos((string) @file_get_contents($scripted->dir() . '/test.retry.jsonl'), 'the-site-secret') === false);
$scripted->append('test', array('n' => 2), 1000000);
$scripted->sent = array();
$scripted->drain('test', 60, true, $send);
check('it is sent again first, then the new rows', count($scripted->sent) === 2
    && $scripted->sent[0][1]['rows'] === array(array('n' => 1)) && $scripted->sent[1][1]['rows'] === array(array('n' => 2)));
check('and is gone once taken', !$scripted->waiting('test'));
$scripted->append('test', array('n' => 3), 1000000);
$scripted->answers = array(400);
$scripted->drain('test', 60, true, $send);
check('a batch the collector refused is not kept', !$scripted->waiting('test'));
// A writer killed mid-line left no newline: the next line starts on its own.
file_put_contents($scripted->dir() . '/test.jsonl', "{\"n\":4}\n{\"n\":5,\"half");
$scripted->append('test', array('n' => 6), 1000000);
$scripted->sent = array();
$scripted->drain('test', 60, true, $send);
check('a half line left by a killed writer loses only itself', count($scripted->sent) === 1
    && $scripted->sent[0][1]['rows'] === array(array('n' => 4), array('n' => 6)));

// A 304 keeps the interval the dashboard last gave; a failure retries sooner.
$scripted->writePhp('switches.php', array('fetched' => 0, 'sync' => 600, 'etag' => '"v1"', 'modules' => array()));
$fresh = new ScriptedCore($options);
$fresh->answers = array(304);
$fresh->syncSwitches();
$after = $fresh->readPhp('switches.php');
check('a 304 keeps the dashboard\'s interval', $after['sync'] === 600 && $after['fetched'] > 0);
$fresh->answers = array(0);
$fresh->syncSwitches(true);
check('an unreachable collector is tried again within a minute', $fresh->readPhp('switches.php')['sync'] === Core::RETRY);

// The check-in on the switches request (X-Platform-App): which site's PHP is
// asking, form-encoded so any name is plain ASCII, and "request", since PHP
// has no process to watch between requests.
parse_str((new Core(array('site_id' => str_repeat('a', 24), 'secret' => 's', 'endpoint' => 'http://c', 'server_name' => 'web wörker')))->checkIn(), $app);
check('the check-in names the server', $app['server'] === 'web wörker');
check('PHP checks in per request', $app['kind'] === 'request' && strpos($app['runtime'], 'PHP ') === 0);
$named = (new Core(array('site_id' => str_repeat('a', 24), 'secret' => 's', 'endpoint' => 'http://c')))->checkIn();
check('without server_name, the host name, in plain ASCII', strpos($named, 'server=') === 0 && !preg_match('/[^\x20-\x7e]/', $named));

foreach (glob($core->dir() . '/*') ?: array() as $path) {
    @unlink($path);
}
@unlink($core->dir() . '/.htaccess');
@rmdir($core->dir());
@rmdir($store);

echo ($failed ? "FAILED" : "OK") . ": $checked checks, $failed failed\n";
exit($failed ? 1 : 0);
