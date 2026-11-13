<?php
// The security headers taken from the platform config, against the cases every
// client shares: sdk/protocols/header-cases.json. Only the nine the dashboard
// can produce get through, so all the packages add the same ones. The
// WordPress plugin's Core.php is the same file (PluginSyncTest).
//
//   php test/HeadersTest.php

require __DIR__ . '/../src/Core.php';

use AnalyticsPlatform\Core;

$casesFile = __DIR__ . '/../../protocols/header-cases.json';
if (!is_file($casesFile)) {
    echo "SKIP: the shared protocol fixtures are not alongside this package\n";
    exit(0);
}
$cases = json_decode((string) file_get_contents($casesFile), true);
if (!is_array($cases) || empty($cases['cases'])) {
    fwrite(STDERR, "Could not read the shared cases.\n");
    exit(1);
}

$failed = 0;
$checked = 0;
foreach ($cases['cases'] as $case) {
    $value = str_repeat($case['value'], isset($case['repeat']) ? $case['repeat'] : 1);
    $checked++;
    if ((bool) Core::safeHeader(array($case['name'], $value)) !== $case['ok']) {
        $failed++;
        printf("FAIL %s: %s should be %s\n", json_encode($case['name']), json_encode(substr($case['value'], 0, 40)), $case['ok'] ? 'added' : 'dropped');
    }
}
foreach (array(null, 'X-Frame-Options', array('X-Frame-Options'), array('X-Frame-Options', 1), array('X-Frame-Options', 'DENY', 'x')) as $pair) {
    $checked++;
    if (Core::safeHeader($pair)) {
        $failed++;
        printf("FAIL %s should be dropped\n", json_encode($pair));
    }
}

printf("%d checks, %d failed\n", $checked, $failed);
exit($failed ? 1 : 0);
