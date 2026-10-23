<?php
// Software inventory: what composer.lock yields, and `direct` -- the mark
// that separates the packages the site asks for from the ones those depend
// on (sdk/protocols/inventory.md).
//
//   php test/InventoryTest.php
// (No dependencies: the package has none, so this is plain PHP, not PHPUnit.)

require __DIR__ . '/../src/Core.php';
require __DIR__ . '/../src/Inventory.php';

use AnalyticsPlatform\Core;
use AnalyticsPlatform\Inventory;

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

$root = sys_get_temp_dir() . '/inventory-test-' . getmypid();
@mkdir($root, 0700, true);

file_put_contents($root . '/composer.lock', json_encode(array(
    'packages' => array(
        array('name' => 'guzzlehttp/guzzle', 'version' => 'v7.8.1'),
        array('name' => 'guzzlehttp/psr7', 'version' => '2.6.2'),
        array('name' => 'monolog/monolog', 'version' => '3.5.0'),
        array('name' => 'broken/nothing'),
    ),
    'packages-dev' => array(
        array('name' => 'phpunit/phpunit', 'version' => '10.5.0'),
    ),
)));

$core = new Core(array('site_id' => str_repeat('a', 24), 'secret' => 'test-secret', 'endpoint' => 'https://example.invalid'));
$inventory = new Inventory($core, array('root' => $root));

$packages = $inventory->composerPackages();
$byName = array();
foreach ($packages as $package) {
    $byName[$package['name']] = $package;
}

check('reads composer.lock, leaving packages-dev out', count($packages) === 3 && !isset($byName['phpunit/phpunit']));
check('drops the leading v from a version', isset($byName['guzzlehttp/guzzle']) && $byName['guzzlehttp/guzzle']['version'] === '7.8.1');
check('every package is Packagist', $byName['monolog/monolog']['ecosystem'] === 'Packagist');
check('skips an entry with no version', !isset($byName['broken/nothing']));

// Without a composer.json nothing is marked, and the list still goes up.
check('no manifest, nothing marked', !isset($byName['guzzlehttp/guzzle']['direct']));

file_put_contents($root . '/composer.json', json_encode(array(
    'require' => array(
        'php' => '>=8.1',
        'ext-json' => '*',
        'lib-curl' => '*',
        'GuzzleHttp/Guzzle' => '^7.0',
    ),
    'require-dev' => array('phpunit/phpunit' => '^10'),
)));

$marked = array();
foreach ($inventory->composerPackages() as $package) {
    $marked[$package['name']] = $package;
}

check('marks what composer.json requires', !empty($marked['guzzlehttp/guzzle']['direct']));
check('a dependency of a dependency is not marked', !isset($marked['guzzlehttp/psr7']['direct']));
check('matches the name whatever its case, as Composer does', !empty($marked['guzzlehttp/guzzle']['direct']));
check('require-dev is not a choice this list carries', !isset($marked['monolog/monolog']['direct']));

$names = $inventory->requiredNames($root . '/composer.lock');
check('php itself is a requirement, not a package', !isset($names['php']));
check('ext- and lib- entries are left out', !isset($names['ext-json']) && !isset($names['lib-curl']));
check('the one real requirement is kept, lower-cased', isset($names['guzzlehttp/guzzle']) && count($names) === 1);

@unlink($root . '/composer.lock');
@unlink($root . '/composer.json');
@rmdir($root);

echo ($failed ? "FAILED" : "OK") . ": $checked checks, $failed failed\n";
exit($failed ? 1 : 0);
