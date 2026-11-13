<?php
// The type a collector answer is served with from the site's own domain,
// against the cases every client shares: sdk/protocols/proxy-answer-cases.json.
// The WordPress plugin's Proxy.php is the same file (PluginSyncTest).
//
//   php test/ProxyAnswerTest.php

require __DIR__ . '/../src/Proxy.php';

use AnalyticsPlatform\Proxy;

$casesFile = __DIR__ . '/../../protocols/proxy-answer-cases.json';
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
    $checked++;
    $served = Proxy::answerType($case['type']);
    if ($served !== $case['served']) {
        $failed++;
        printf("FAIL %s was served as %s, not %s\n", json_encode($case['type']), $served, $case['served']);
    }
}

printf("%d checks, %d failed\n", $checked, $failed);
exit($failed ? 1 : 0);
