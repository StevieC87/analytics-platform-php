<?php
// Whose address the firewall believes. Behind Cloudflare the visitor is in
// CF-Connecting-IP, but anyone who reaches the origin directly can send that
// header too, and would pick their own address past every rule.
//
//   php test/FirewallTest.php
// (No dependencies: the package has none, so this is plain PHP, not PHPUnit.)

require __DIR__ . '/../src/Core.php';
require __DIR__ . '/../src/RequestRules.php';
require __DIR__ . '/../src/Firewall.php';

use AnalyticsPlatform\Firewall;

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

$firewall = new Firewall(array(
    'site_id' => 'a1b2c3d4e5f6a1b2c3d4e5f6', 'secret' => 's', 'endpoint' => 'https://collector.example',
    'storage' => sys_get_temp_dir() . '/analytics-firewall-test-' . getmypid(), 'trust_proxy' => 'cloudflare',
));

$_SERVER['HTTP_CF_CONNECTING_IP'] = '198.51.100.7';
$_SERVER['REMOTE_ADDR'] = '172.68.10.20';
check('the header is believed from a Cloudflare address', $firewall->clientIp() === '198.51.100.7');
$_SERVER['REMOTE_ADDR'] = '2606:4700:10::6816:1';
check('and from a Cloudflare IPv6 address', $firewall->clientIp() === '198.51.100.7');
$_SERVER['REMOTE_ADDR'] = '203.0.113.50';
check('not from anyone else, who gets their own address', $firewall->clientIp() === '203.0.113.50');
unset($_SERVER['HTTP_CF_CONNECTING_IP']);
$_SERVER['REMOTE_ADDR'] = '172.68.10.20';
check('without the header, the connection is the address', $firewall->clientIp() === '172.68.10.20');

$shared = __DIR__ . '/../../protocols/cloudflare-ranges.json';
if (is_file($shared)) {
    $list = json_decode((string) file_get_contents($shared), true);
    check('the ranges are the shared list', is_array($list) && $list['ranges'] === Firewall::CLOUDFLARE);
}

echo ($failed ? "FAILED" : "OK") . ": $checked checks, $failed failed\n";
exit($failed ? 1 : 0);
