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

foreach (glob($core->dir() . '/*') ?: array() as $path) {
    @unlink($path);
}
@unlink($core->dir() . '/.htaccess');
@rmdir($core->dir());
@rmdir($store);

echo ($failed ? "FAILED" : "OK") . ": $checked checks, $failed failed\n";
exit($failed ? 1 : 0);
