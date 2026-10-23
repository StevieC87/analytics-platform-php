<?php
// The WordPress plugin carries its own copy of every class in src/, because a
// plugin cannot depend on Composer. Nothing copies them, so they drift — and
// drift is silent: Platform builds each module inside a try/catch, so a class
// the plugin forgot to load just never runs, and a method the plugin's older
// copy doesn't have only shows up as a fatal in WP-Cron once a day.
//
// Three features were lost that way before this test existed: request rules
// (V6) were never applied on WordPress, the posture module (V5) was never
// built, and crawler reporting was off because the plugin's class list didn't
// name it.
//
//   php test/PluginSyncTest.php

$src = __DIR__ . '/../src';
$lib = __DIR__ . '/../../wordpress-plugin/site-analytics/lib';
$plugin = __DIR__ . '/../../wordpress-plugin/site-analytics/site-analytics.php';

// This package is published on its own, and a Packagist repo holds only what
// Composer installs — so the plugin is not always a sibling. Drift can only be
// checked from the full tree; outside it there is nothing to compare against.
if (!is_dir($lib) || !is_file($plugin)) {
    echo "SKIP: the WordPress plugin is not alongside this package, so drift cannot be checked\n";
    exit(0);
}

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

foreach (glob($src . '/*.php') ?: array() as $path) {
    $name = basename($path);
    $copy = $lib . '/' . $name;
    if (!is_file($copy)) {
        check("the plugin carries $name", false);
        continue;
    }
    check(
        "$name is the same in the plugin as in src/ (copy it across)",
        md5_file($path) === md5_file($copy)
    );
}

// Every class Platform builds has to be loaded by the plugin first, or the
// try/catch around it turns that module off without a word.
$platform = (string) file_get_contents($src . '/Platform.php');
preg_match_all('/new ([A-Z][A-Za-z]*)\s*\(/', $platform, $used);
$loaded = array();
if (preg_match('/foreach \(array\(((?:\s*\'[A-Za-z]+\',?)+)\) as \$class\)/', (string) file_get_contents($plugin), $list)) {
    preg_match_all("/'([A-Za-z]+)'/", $list[1], $names);
    $loaded = $names[1];
}
check('the plugin has a class list', !empty($loaded));
foreach (array_unique($used[1]) as $class) {
    check("the plugin loads $class, which Platform builds", in_array($class, $loaded, true));
}

echo ($failed ? "FAILED" : "OK") . ": $checked checks, $failed failed\n";
exit($failed ? 1 : 0);
