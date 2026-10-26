<?php
// The request-rule matcher (virtual patching), against the cases every client
// shares: sdk/protocols/request-rules-cases.json. The Node and Python packages
// run the same file, so the matchers decide alike.
//
//   php test/RequestRulesTest.php
// (No dependencies: the package has none, so this is plain PHP, not PHPUnit.)

require __DIR__ . '/../src/RequestRules.php';

use AnalyticsPlatform\RequestRules;

// The cases are the cross-language parity fixture, shared with the Node and
// Python clients. It is deliberately not copied in here — a copy would drift
// silently, which is the whole thing these fixtures exist to prevent.
$casesFile = __DIR__ . '/../../protocols/request-rules-cases.json';
if (!is_file($casesFile)) {
    echo "SKIP: the shared protocol fixtures are not alongside this package\n";
    exit(0);
}
$cases = json_decode((string) file_get_contents($casesFile), true);
if (!is_array($cases) || empty($cases['requests'])) {
    fwrite(STDERR, "Could not read the shared cases.\n");
    exit(1);
}

$failed = 0;
$checked = 0;
$rules = RequestRules::compile(array('rules' => $cases['rules']));

foreach ($cases['requests'] as $request) {
    $matched = RequestRules::matchRequest($rules, $request['method'], $request['target'], $request['ua']);
    $got = $matched ? $matched['id'] : null;
    $checked++;
    if ($got !== $request['expect']) {
        $failed++;
        printf("FAIL %s %s\n  %s\n  expected %s, got %s\n", $request['method'], $request['target'],
            $request['why'], var_export($request['expect'], true), var_export($got, true));
    }
}

// The regex guard, against the same lists the backend and collector check.
foreach (array('refused' => false, 'allowed' => true) as $list => $want) {
    foreach (isset($cases['patterns'][$list]) ? $cases['patterns'][$list] : array() as $pattern) {
        $checked++;
        if (RequestRules::safePattern($pattern) !== $want) {
            $failed++;
            printf("FAIL safePattern(%s) should be %s\n", $pattern, $want ? 'allowed' : 'refused');
        }
    }
}

// The same edge cases the other packages check.
$empty = RequestRules::compile(array('rules' => array(array('id' => 'empty', 'action' => 'block'))));
$checked++;
if ($empty !== array()) {
    $failed++;
    echo "FAIL a rule with nothing to match should be dropped\n";
}
$mixed = RequestRules::compile(array('rules' => array(
    array('id' => 'bad', 'action' => 'block', 'path' => array('regex' => '([')),
    array('id' => 'good', 'action' => 'block', 'path' => array('exact' => array('/shell.php'))),
)));
$checked++;
if (count($mixed) !== 1 || RequestRules::matchRequest($mixed, 'GET', '/shell.php', '')['id'] !== 'good') {
    $failed++;
    echo "FAIL a pattern that doesn't compile should be dropped, the rest kept\n";
}
$checked++;
if (RequestRules::matchRequest(array(), 'GET', '/../../etc/passwd', '') !== null) {
    $failed++;
    echo "FAIL no rules should mean no match\n";
}
$many = array();
for ($i = 0; $i < 250; $i++) {
    $many[] = array('id' => 'r' . $i, 'action' => 'monitor', 'path' => array('exact' => array('/' . $i)));
}
$checked++;
if (count(RequestRules::compile(array('rules' => $many))) !== 200) {
    $failed++;
    echo "FAIL at most 200 rules should be compiled\n";
}

// (a+)+ takes exponential time on input that nearly matches, and PCRE can't be
// timed out here: the client must refuse the pattern, not match it.
foreach (array('(a+)+b', '(a*)*', '(ab|cd+)+', '(a)\\1', '(?<=x)y', 'unbalanced(') as $pattern) {
    $checked++;
    if (RequestRules::safePattern($pattern)) {
        $failed++;
        printf("FAIL a pattern that can blow up should be refused: %s\n", $pattern);
    }
}
foreach (array('/(wp-content/uploads|uploads)/[^?]*\\.(php[0-9]?|phtml)$', '(includes|inc|lib)?/?[^/]*\\.php$') as $pattern) {
    $checked++;
    if (!RequestRules::safePattern($pattern)) {
        $failed++;
        printf("FAIL a starter pattern should be allowed: %s\n", $pattern);
    }
}
$unsafe = RequestRules::compile(array('rules' => array(
    array('id' => 'slow', 'action' => 'block', 'path' => array('regex' => '(a+)+b')),
    array('id' => 'fine', 'action' => 'block', 'path' => array('exact' => array('/x'))),
)));
$checked++;
if (count($unsafe) !== 1 || $unsafe[0]['id'] !== 'fine') {
    $failed++;
    echo "FAIL an unsafe rule should be dropped and the rest kept\n";
}
$started = microtime(true);
RequestRules::matchRequest($unsafe, 'GET', '/' . str_repeat('a', 100000) . '!', '');
$checked++;
if (microtime(true) - $started > 1.0) {
    $failed++;
    echo "FAIL matching should stay quick on a long path\n";
}

printf("%d checks, %d failed\n", $checked, $failed);
exit($failed ? 1 : 0);
