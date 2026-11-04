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

// An IPv6 range that holds all of ::ffff:0:0/96 would match every IPv4
// visitor (IPv4 is kept as ::ffff:a.b.c.d): dropped from any list.
foreach (array('::/64', '::ffff:0:0/64', '::/0', '::ffff:0:0/96', '::/8') as $wide) {
    check("$wide is refused", Firewall::range($wide) === null);
    check("$wide matches no IPv4 visitor", !Firewall::inList(Firewall::compileList(array($wide)), Firewall::ipKey('203.0.113.9')));
}
check('an IPv4 range written as IPv6 still counts', Firewall::inList(Firewall::compileList(array('::ffff:203.0.113.0/120')), Firewall::ipKey('203.0.113.9')));
check('an ordinary IPv6 /64 still counts', Firewall::inList(Firewall::compileList(array('2001:db8:0:1::/64')), Firewall::ipKey('2001:db8:0:1::9')));
check('and a plain IPv4 range', Firewall::inList(Firewall::compileList(array('203.0.113.0/24', '::/64')), Firewall::ipKey('203.0.113.9')));

echo ($failed ? "FAILED" : "OK") . ": $checked checks, $failed failed\n";
exit($failed ? 1 : 0);
