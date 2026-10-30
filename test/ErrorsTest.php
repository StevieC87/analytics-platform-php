<?php
// The errors module: an error is sent once however many handlers see it, the
// route setRoute() names goes with it, and a batch the collector couldn't
// take waits on disk for a later request.
//
//   php test/ErrorsTest.php
// (No dependencies: the package has none, so this is plain PHP, not PHPUnit.)

foreach (glob(__DIR__ . '/../src/*.php') as $file) {
    require_once $file;
}

use AnalyticsPlatform\Core;
use AnalyticsPlatform\Errors;

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

class ScriptedCore extends Core
{
    public $answers = array();
    public $sent = array();

    public function http($method, $path, $body = null, array $headers = array(), $auth = 'bearer')
    {
        $this->sent[] = array($path, $body);
        $status = $this->answers ? array_shift($this->answers) : 202;
        return array('status' => $status, 'body' => '', 'headers' => array());
    }

    public function isOn($name)
    {
        return true;
    }
}

$store = sys_get_temp_dir() . '/analytics-errors-test-' . getmypid();
$core = new ScriptedCore(array('site_id' => 'a1b2c3d4e5f6a1b2c3d4e5f6', 'secret' => 'the-site-secret',
    'endpoint' => 'https://collector.example', 'storage' => $store));
$core->ensureDir();
$_SERVER['REQUEST_METHOD'] = 'POST';
$_SERVER['REQUEST_URI'] = '/orders/12?x=1';

$sentErrors = function () use ($core) {
    $all = array();
    foreach ($core->sent as $sent) {
        $all = array_merge($all, $sent[1]['errors']);
    }
    return $all;
};

$errors = new Errors($core);
$errors->setRoute('/orders/{id}');
$error = new RuntimeException('payment failed');
$errors->captureException($error, null, 500, 'error');
$errors->captureException($error, null, 0, 'logged');
$errors->captureException(new RuntimeException('payment failed'));
$errors->flush();
$events = $sentErrors();
check('one error seen twice is sent once; another with the same message is sent', count($events) === 2);
check('the route setRoute() named goes with it', $events[0]['route'] === '/orders/{id}' && $events[0]['path'] === '/orders/12');
check('the first capture decides its kind', $events[0]['kind'] === 'error');

// Logged first, then reported: one event, with the report's status and kind.
$core->sent = array();
$errors->setRoute('');
$logged = new RuntimeException('charge failed');
$errors->captureException($logged, array('method' => 'POST', 'path' => '/pay'), 0, 'logged');
$errors->captureException($logged, null, 500, 'error');
$errors->flush();
$events = $sentErrors();
check('logged then reported is one event', count($events) === 1);
check('with the report\'s status and kind', $events[0]['status_code'] === 500 && $events[0]['kind'] === 'error');
check('without setRoute, the route is named as Server speed names it', $events[0]['route'] === '/pay');
$errors->captureException($logged, null, 500, 'error');
$errors->flush();
check('once sent, the error is forgotten (a long-running worker keeps no exceptions)', count($sentErrors()) === 2);

$core->sent = array();
$core->answers = array(503, 503);
$errors->captureException(new RuntimeException('collector away'));
$errors->flush();
check('a batch the collector could not take waits on disk', $core->waiting('errors'));
check('it is not sent again within the minute', !$errors->due());
@touch($core->dir() . '/errors.lock', time() - 120);
check('a minute later it is due', $errors->due());
$core->sent = array();
$errors->flush();
check('and a later request sends it', count($core->sent) === 1 && $core->sent[0][1]['errors'][0]['message'] === 'collector away');
check('then nothing is left waiting', !$core->waiting('errors'));

$core->answers = array(400);
$errors->captureException(new RuntimeException('refused'));
$errors->flush();
check('a batch the collector refused is not kept', !$core->waiting('errors'));

// A job through Platform: its errors carry the job's name, its run is timed,
// and on the command line they're sent when it ends (here the collector is
// away, so they wait on disk).
$jobStore = $store . '-job';
$platform = new AnalyticsPlatform\Platform(array('site_id' => 'a1b2c3d4e5f6a1b2c3d4e5f6', 'secret' => 'the-site-secret',
    'endpoint' => 'http://127.0.0.1:9', 'storage' => $jobStore, 'server_name' => 'worker', 'firewall' => false, 'proxy' => false));
$thrown = null;
try {
    $platform->job('send-receipts', function () {
        throw new RuntimeException('receipt failed');
    });
} catch (RuntimeException $e) {
    $thrown = $e;
}
check('the job\'s exception is thrown on', $thrown !== null && $thrown->getMessage() === 'receipt failed');
$jobDir = glob($jobStore . '/*', GLOB_ONLYDIR)[0];
$kept = (string) @file_get_contents($jobDir . '/errors.retry.jsonl');
check('its error waits with the job as its route, the service name and when it happened',
    strpos($kept, '"route":"\/(job) send-receipts"') !== false && strpos($kept, '"method":"JOB"') !== false
    && strpos($kept, '"server_name":"worker"') !== false && preg_match('/"at":"\d{4}-\d\d-\d\dT/', $kept) === 1);
// Sent at once (the command line), so the collector being away left it in the resend file.
$timed = (string) @file_get_contents($jobDir . '/requests.retry.jsonl');
check('and the run is timed as a failed job', strpos($timed, '"method":"JOB"') !== false && strpos($timed, '"status":500') !== false
    && strpos($timed, '"route":"\/(job) send-receipts"') !== false);
// A job inside a job: the outer one's error keeps its name, and both runs are timed.
@unlink($jobDir . '/errors.retry.jsonl');
@unlink($jobDir . '/requests.retry.jsonl');
try {
    $platform->job('nightly', function () use ($platform) {
        $platform->job('one-step', function () {
        });
        throw new RuntimeException('nightly failed');
    });
} catch (RuntimeException $e) {
}
$kept = (string) @file_get_contents($jobDir . '/errors.retry.jsonl');
check('after an inner job, the outer job\'s error is named after the outer job', strpos($kept, '"route":"\/(job) nightly"') !== false);
// Within the minute of the first job's flush, so these wait in the requests file.
$timed = (string) @file_get_contents($jobDir . '/requests.jsonl') . (string) @file_get_contents($jobDir . '/requests.retry.jsonl');
check('and both runs are timed', strpos($timed, '(job) one-step') !== false && strpos($timed, '(job) nightly') !== false);
foreach (glob($jobDir . '/{,.}*', GLOB_BRACE) ?: array() as $path) {
    if (is_file($path)) {
        @unlink($path);
    }
}
@rmdir($jobDir);
@rmdir($jobStore);

// The trail: an error carries the steps before it, and only its own.
$core->sent = array();
$trail = new Errors($core);
$trail->captureException(new RuntimeException('no steps yet'));
for ($i = 0; $i < 20; $i++) {
    $trail->addBreadcrumb('step ' . $i);
}
$trail->addRequestBreadcrumb('post', 'https://api.example/charge?card=4242#top', 502);
$trail->addRequestBreadcrumb('GET', 'https://api.example/down', 0);
$trail->captureException(new RuntimeException('after the steps'));
$trail->clearBreadcrumbs();
$trail->captureException(new RuntimeException('next request'));
$trail->addBreadcrumb('in a job');
$trail->setJob('/(job) one');
$trail->captureException(new RuntimeException('in the job'));
$trail->flush();
$sent = $sentErrors();
$crumbs = isset($sent[1]['breadcrumbs']) ? $sent[1]['breadcrumbs'] : array();
check('an error before any step has no trail', !isset($sent[0]['breadcrumbs']));
check('the trail keeps the last 15 steps', count($crumbs) === 15 && $crumbs[0]['text'] === 'step 7');
check('a request has its method and status, and no query string', $crumbs[13] === array('type' => 'request', 'text' => 'POST https://api.example/charge', 'status' => 502, 'ms' => $crumbs[13]['ms']));
check('no answer is status 0', $crumbs[14]['status'] === 0 && $crumbs[14]['text'] === 'GET https://api.example/down');
check('steps carry how long ago, not when', is_int($crumbs[0]['ms']) && !isset($crumbs[0]['at']));
check('the next request starts a new trail', !isset($sent[2]['breadcrumbs']));
check('a job starts a new trail', !isset($sent[3]['breadcrumbs']));

foreach (glob($core->dir() . '/*') ?: array() as $path) {
    @unlink($path);
}
@unlink($core->dir() . '/.htaccess');
@rmdir($core->dir());
@rmdir($store);

echo ($failed ? "FAILED" : "OK") . ": $checked checks, $failed failed\n";
exit($failed ? 1 : 0);
