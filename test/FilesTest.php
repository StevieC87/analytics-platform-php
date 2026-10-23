<?php
// File monitoring: what the walk includes, and that only facts about a file
// ever leave the server -- never what is in it.
//
//   php test/FilesTest.php
// (No dependencies: the package has none, so this is plain PHP, not PHPUnit.)

require __DIR__ . '/../src/Core.php';
require __DIR__ . '/../src/Files.php';

use AnalyticsPlatform\Core;
use AnalyticsPlatform\Files;

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

$site = sys_get_temp_dir() . '/analytics-files-test-' . getmypid();
$store = $site . '-store';
@mkdir($site . '/uploads', 0775, true);

$write = function ($name, $body) use ($site) {
    $path = $site . '/' . $name;
    @mkdir(dirname($path), 0775, true);
    file_put_contents($path, $body);
    return $path;
};

$secret = "<?php\n\$db_password = 'hunter2-do-not-leak';\n";
$config = $write('config.php', $secret);
$shell = $write('bad.php', '<?php eval(base64_decode($_GET["x"])); ');
$write('fine.js', "console.log('hello');\n");
$write('logo.png', "\x89PNG\r\n");
@symlink('/etc/passwd', $site . '/sneaky.php');

$core = new Core(array('site_id' => 'a1b2c3d4e5f6a1b2c3d4e5f6', 'secret' => 's', 'endpoint' => 'https://c.example', 'storage' => $store));
$files = new Files($core, array('roots' => array($site)));

// scan() is private: this is the walk itself, without the reporting around it.
$scan = new ReflectionMethod($files, 'scan');
$scan->setAccessible(true);
list($current, $truncated) = $scan->invoke($files, array(), true);

check('a watched file is hashed', isset($current[$config]) && isset($current[$shell]));
check('a script is watched too', isset($current[$site . '/fine.js']));
check('an image is not watched', !isset($current[$site . '/logo.png']));
check('a symlink is never followed', !isset($current[$site . '/sneaky.php']));
check('nothing was truncated', $truncated === false);
check('what is kept is a sha256, a size and a time', isset($current[$config])
    && preg_match('/^[a-f0-9]{64}$/', $current[$config][0])
    && $current[$config][1] === strlen($secret));

// The one property that matters most: the contents stay on the server.
check('a file\'s contents never appear in what is kept', strpos(json_encode($current), 'hunter2') === false);

$signals = Files::signals($shell);
check('a web shell is recognised', in_array('eval_decode', $signals, true));
check('an ordinary file raises nothing', Files::signals($site . '/fine.js') === array());
check('the signal names carry no contents', strpos(json_encode($signals), 'hunter2') === false);

$inUploads = $write('uploads/shell.php', '<?php echo 1;');
check('php in an uploads folder is flagged on its path alone', in_array('code_in_uploads', Files::signals($inUploads), true));

// The budget that keeps one scan from reading the whole site.
check('there is a cap on how many files get read', Files::MAX_SIGNAL_FILES > 0 && Files::MAX_SIGNAL_FILES <= Files::MAX_FILES);

$excluded = new Files($core, array('roots' => array($site), 'exclude' => array($site . '/uploads')));
$scan2 = new ReflectionMethod($excluded, 'scan');
$scan2->setAccessible(true);
list($some) = $scan2->invoke($excluded, array(), true);
check('an excluded folder is skipped', !isset($some[$inUploads]) && isset($some[$config]));

foreach (array($site . '/uploads/shell.php', $site . '/sneaky.php', $config, $shell, $site . '/fine.js', $site . '/logo.png') as $path) {
    @unlink($path);
}
@rmdir($site . '/uploads');
@rmdir($site);
foreach (glob($store . '/*/*') ?: array() as $path) {
    @unlink($path);
}

echo ($failed ? "FAILED" : "OK") . ": $checked checks, $failed failed\n";
exit($failed ? 1 : 0);
