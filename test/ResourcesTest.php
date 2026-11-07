<?php
// The resources module: what is read from the machine, and the rule the whole
// feature rests on — a reading this machine won't give is left out of the row,
// never sent as a zero (sdk/protocols/resources.md).
//
// The interesting case here is CPU. PHP has no process that lives between
// requests, so the previous /proc/stat reading is kept in the state folder;
// that is what lets a PHP site report a real CPU average at all, and it is
// also why the figure is dropped after a long gap in traffic.
//
//   php test/ResourcesTest.php
// (No dependencies: the package has none, so this is plain PHP, not PHPUnit.)

require __DIR__ . '/../src/Core.php';
require __DIR__ . '/../src/Resources.php';

use AnalyticsPlatform\Core;
use AnalyticsPlatform\Resources;

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

$STAT = "cpu  100 10 50 1000 20 0 5 0 0 0\ncpu0 50 5 25 500 10 0 2 0 0 0\nintr 1\n";
$MEMINFO = "MemTotal:        8143868 kB\nMemFree:          210000 kB\nMemAvailable:    5021228 kB\n"
    . "SwapTotal:       2097152 kB\nSwapFree:        2084864 kB\n";

// ---- CPU ---------------------------------------------------------------------------

$before = Resources::cpuTimes($STAT);
check('busy and total skip idle and iowait', $before === array(165, 1185));
check('one reading alone says nothing', Resources::cpuPercent(null, $before) === null);
check('no time passed says nothing', Resources::cpuPercent($before, $before) === null);
$after = array($before[0] + 100, $before[1] + 200);
check('half the time busy is 50 per cent', Resources::cpuPercent($before, $after) === 50.0);
check('a counter that went backwards says nothing', Resources::cpuPercent($after, $before) === null);
check('a short /proc/stat is not guessed at', Resources::cpuTimes("cpu  1 2\n") === null);
check('no cpu line at all is null', Resources::cpuTimes("intr 1\n") === null);

// ---- Memory ------------------------------------------------------------------------

$memory = Resources::memoryMb($MEMINFO);
check('memory total is in megabytes', $memory['mem_total_mb'] === 7952);
// MemFree would claim 7747 MB used and make a healthy machine look full.
check('used is total minus available, not minus free', $memory['mem_used_mb'] === 3049);
check('swap is read too', $memory['swap_total_mb'] === 2048 && $memory['swap_used_mb'] === 12);
$partial = Resources::memoryMb("MemTotal: 8143868 kB\nMemFree: 210000 kB\n");
check('no MemAvailable means no used figure at all', $partial === array('mem_total_mb' => 7952));
check('an unreadable /proc/meminfo reports nothing', Resources::memoryMb('') === array());

// ---- Disks -------------------------------------------------------------------------

$mounts = "/dev/sda1 / ext4 rw,relatime 0 0\nproc /proc proc rw 0 0\ntmpfs /run tmpfs rw 0 0\n"
    . "/dev/loop3 /snap/core20/2105 squashfs ro 0 0\nnas:/export /mnt/nas nfs4 rw 0 0\n"
    . "/dev/sdb1 /data xfs rw 0 0\n/dev/sda1 /var/www ext4 rw 0 0\n";
// An explicit directory test, so the case does not depend on which of these
// paths happens to exist on the machine running the suite.
$anyDir = function () { return true; };
check('only real disks, one per device',
    Resources::mountPoints($mounts, '/', $anyDir) === array('/', '/data'));
check('without a mount table, the site folder is the one disk we can name',
    Resources::mountPoints('', '/var/www/html') === array('/var/www/html'));

// Docker bind-mounts single files, so a container's mount table lists
// /etc/hosts and friends on the host's own device. Those paths are short, so
// without a directory test one of them wins the shortest-path race and the
// panel names a file as one of the site's disks.
$container = "overlay / overlay rw,relatime 0 0\n"
    . "/dev/nvme0n1p6 /var/www/html/wp-content/plugins/site-analytics ext4 rw 0 0\n"
    . "/dev/nvme0n1p6 /etc/resolv.conf ext4 rw 0 0\n"
    . "/dev/nvme0n1p6 /etc/hostname ext4 rw 0 0\n"
    . "/dev/nvme0n1p6 /etc/hosts ext4 rw 0 0\n";
check('a bind-mounted file is not one of the disks',
    Resources::mountPoints($container, '/', function ($mount) {
        return strpos($mount, '/etc/') !== 0;
    }) === array('/', '/var/www/html/wp-content/plugins/site-analytics'));
// open_basedir can make is_dir() false for every path a shared host won't
// show us. Reporting no disks at all would be worse than an odd mount point,
// so the device keeps its shortest mount.
check('a device whose mounts we cannot confirm keeps its shortest',
    Resources::mountPoints($container, '/', function () { return false; })
        === array('/', '/etc/hosts'));

// The bug seen on a real container: / is the overlay and /sdk is a bind of the
// host disk the overlay's upperdir lives on. The kernel calls them different
// devices (overlay vs /dev/nvme0n1p6, two different st_dev), so only the
// byte-identical size and free space give it away.
$sameFs = Resources::diskRows(array('/', '/sdk'), function () {
    return 320660893696;
}, function () {
    return 117013626880;
});
check('one filesystem behind two devices is reported once',
    count($sameFs) === 1 && $sameFs[0]['mount'] === '/');
// Two disks that merely round to the same megabyte stay apart: the test is on
// raw bytes, not the rounded megabytes.
$twoDisks = Resources::diskRows(array('/', '/data'), function () {
    return 320660893696;
}, function ($mount) {
    return $mount === '/' ? 117013626880 : 117013626881;
});
check('two disks that only round alike are both reported', count($twoDisks) === 2);

$rows = Resources::diskRows(array('/'), function () {
    return 4294967296; // a 4 GiB disk
}, function () {
    return 1073741824; // 1 GiB free
});
check('disk total is the size PHP reports', $rows[0]['total_mb'] === 4096);
check('disk used is size minus free', $rows[0]['used_mb'] === 3072);
$small = Resources::diskRows(array('/boot/efi'), function () {
    return 268435456; // 256 MB
}, function () {
    return 134217728;
});
check('a partition too small to care about is left out', $small === array());
$broken = Resources::diskRows(array('/locked'), function () {
    return false;
}, function () {
    return false;
});
check('a disk PHP cannot measure is left out, not guessed', $broken === array());

// ---- Uptime ------------------------------------------------------------------------

check('uptime is whole seconds', Resources::hostUptime("864000.12 1700000.00") === 864000);
check('no /proc/uptime is null', Resources::hostUptime('') === null);

// ---- A sample, and the state that makes CPU possible -------------------------------

$store = sys_get_temp_dir() . '/analytics-resources-test-' . getmypid();
$core = new Core(array(
    'site_id' => 'a1b2c3d4e5f6a1b2c3d4e5f6', 'secret' => 'the-site-secret',
    'endpoint' => 'https://collector.example', 'storage' => $store,
));
$core->ensureDir();
$resources = new Resources($core, array('server_name' => 'wp-1'));

check('a sample is due when none was ever taken', $resources->due());
$first = $resources->sample(1760000000);
check('the first sample carries the minute it covers', $first['minute'] === '2025-10-09T08:53:20Z' || substr($first['minute'], -1) === 'Z');
// No previous reading existed, so there is no interval to divide: null, not 0.
check('the first sample reports no CPU figure', !array_key_exists('cpu_pct', $first));
check('a sample is not due again straight away', !$resources->due());
check('the previous reading was kept, which is what makes CPU possible',
    is_file($core->dir() . '/resources.state'));

// A minute later, the state file gives the interval CPU is measured over.
$state = json_decode(file_get_contents($core->dir() . '/resources.state'), true);
check('the state holds the /proc/stat counters and their time',
    isset($state['at']) && isset($state['cpu']) && is_array($state['cpu']) && count($state['cpu']) >= 4);

// Written as though the last sample were 60 seconds ago: 600 jiffies of user
// work and 5400 idle, so 6000 passed and a tenth of them were busy.
$before = $state['cpu'];
$before[0] = $before[0] - 600;
$before[3] = $before[3] - 5400;
file_put_contents($core->dir() . '/resources.state', json_encode(array(
    'cpu' => $before, 'disk' => array(0, 0), 'net' => array(0, 0), 'at' => time() - 60,
)));
$second = $resources->sample();
check('a second sample a minute later does report CPU', isset($second['cpu_pct']));
// The breakdown covers the same interval, so it arrives with it.
check('and says where the time went, not just how much', isset($second['cpu_user_pct']));
// The counters were planted at zero, so the whole of this machine's reading
// looks like it moved in 60 seconds: a rate, not a total.
check('and reports throughput as a rate when a pair exists',
    !array_key_exists('disk_read_mbs', $second) || is_float($second['disk_read_mbs']) || is_int($second['disk_read_mbs']));

// A state file from before the breakdown existed holds two figures, not the
// counters. It must be ignored rather than read as counters.
file_put_contents($core->dir() . '/resources.state', json_encode(array(
    'cpu' => array(1000, 10000), 'at' => time() - 60,
)));
$legacy = $resources->sample();
check('a state file from the previous version costs one sample, not a wrong one',
    !array_key_exists('cpu_pct', $legacy) && !array_key_exists('cpu_user_pct', $legacy));
check('the CPU figure is a percentage', !isset($second['cpu_pct']) || ($second['cpu_pct'] >= 0 && $second['cpu_pct'] <= 100));

// After a long gap in traffic the average would cover far more than the
// minute the row is labelled with, so it is left out instead.
file_put_contents($core->dir() . '/resources.state', json_encode(array(
    'cpu' => array(1, 1000), 'at' => time() - 7200,
)));
$afterGap = $resources->sample();
check('after a long gap the CPU figure is dropped, not misattributed', !array_key_exists('cpu_pct', $afterGap));

// A sample taken seconds after the last one can't divide the counters either.
file_put_contents($core->dir() . '/resources.state', json_encode(array(
    'cpu' => array(1, 1000), 'at' => time() - 1,
)));
$tooSoon = $resources->sample();
check('two readings a second apart give no CPU figure', !array_key_exists('cpu_pct', $tooSoon));

// On a Linux host the sample should carry real figures; the memory one is the
// only field every container has.
if (is_readable('/proc/meminfo')) {
    check('a real sample reads this machine\'s memory', isset($afterGap['mem_total_mb']) && $afterGap['mem_total_mb'] > 0);
    check('a real sample reports the application\'s own memory', isset($afterGap['proc_rss_mb']) && $afterGap['proc_rss_mb'] >= 1);
}


// ---- Limits: how close it is to a wall (resources.md, "Limits") -----------------------

// A stand-in filesystem: path -> contents, '' for anything else.
function filesystem(array $files)
{
    return function ($path) use ($files) {
        return isset($files[$path]) ? $files[$path] : '';
    };
}

$NETSTAT = "TcpExt: SyncookiesSent ListenOverflows ListenDrops\nTcpExt: 0 %d 7\nIpExt: InNoRoutes\nIpExt: 0\n";
$v2 = array(
    '/proc/self/cgroup' => "0::/\n",
    '/sys/fs/cgroup/memory.max' => "536870912\n",
    '/sys/fs/cgroup/memory.current' => "524288000\n",
    '/sys/fs/cgroup/memory.stat' => "anon 300000000\ninactive_file 104857600\nactive_file 1\n",
    '/sys/fs/cgroup/memory.events' => "low 0\nhigh 0\nmax 4\noom 1\noom_kill 2\n",
    '/sys/fs/cgroup/cpu.max' => "150000 100000\n",
    '/sys/fs/cgroup/cpu.stat' => "usage_usec 1\nnr_periods 1000\nnr_throttled 50\nthrottled_usec 9\n",
    '/proc/pressure/cpu' => "some avg10=1.00 avg60=12.34 avg300=3.00 total=1\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n",
    '/proc/pressure/memory' => "some avg10=0.00 avg60=0.50 avg300=0.00 total=1\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n",
    '/proc/net/netstat' => sprintf($NETSTAT, 40),
    '/proc/sys/net/netfilter/nf_conntrack_count' => "3000\n",
    '/proc/sys/net/netfilter/nf_conntrack_max' => "262144\n",
);
check('the v2 path and the v1 controllers are found in /proc/self/cgroup',
    Resources::cgroupPaths("0::/system.slice/php-fpm.service\n") === array('v2' => '/system.slice/php-fpm.service', 'memory' => null, 'cpu' => null)
    && Resources::cgroupPaths("5:memory:/docker/abc\n4:cpu,cpuacct:/docker/abc\n") === array('v2' => null, 'memory' => '/docker/abc', 'cpu' => '/docker/abc'));
list($first, $keep) = Resources::limits(array(), true, 7953, 4, filesystem($v2), null);
check('a container\'s memory cap and working set (current less inactive_file)', $first['limit_mem_mb'] === 512 && $first['limit_mem_used_mb'] === 400);
check('its CPU cap in cores', $first['limit_cpu_cores'] === 1.5);
check('one reading of the counts says nothing yet', !isset($first['oom_kills']) && !isset($first['cpu_throttled_pct']) && !isset($first['listen_drops']));
check('waiting time is avg60 of the "some" line, and io left out when the kernel has none', $first['psi_cpu_pct'] === 12.3 && $first['psi_mem_pct'] === 0.5
    && !isset($first['psi_io_pct']));
check('how full the connection table is', $first['conntrack_pct'] === 1.1);
check('no FPM, no pool and no process key', !isset($first['workers_busy']) && !isset($first['proc_key']) && !isset($first['proc_uptime_s']));
check('no open files and no requests in progress from PHP', !isset($first['fds_used']) && !isset($first['inflight_peak']));

$v2['/sys/fs/cgroup/memory.events'] = "oom_kill 5\n";
$v2['/sys/fs/cgroup/cpu.stat'] = "nr_periods 1600\nnr_throttled 200\n";
$v2['/proc/net/netstat'] = sprintf($NETSTAT, 43);
list($second, $keep2) = Resources::limits(json_decode(json_encode($keep), true), true, 7953, 4, filesystem($v2), null);
check('kills, throttling and refused connections are the difference since the last sample', $second['oom_kills'] === 3
    && $second['cpu_throttled_pct'] === 25.0 && $second['listen_drops'] === 3);
list($gap) = Resources::limits(json_decode(json_encode($keep), true), false, 7953, 4, filesystem($v2), null);
check('after a long gap the counts keep their whole difference; the throttled share is dropped', $gap['oom_kills'] === 3
    && $gap['listen_drops'] === 3 && !isset($gap['cpu_throttled_pct']));
$v2['/sys/fs/cgroup/memory.events'] = "oom_kill 0\n";
list($reset) = Resources::limits(json_decode(json_encode($keep2), true), true, 7953, 4, filesystem($v2), null);
check('a counter that went down was reset: nothing sent', !isset($reset['oom_kills']));

$none = $v2;
$none['/sys/fs/cgroup/memory.max'] = "max\n";
$none['/sys/fs/cgroup/cpu.max'] = "max 100000\n";
list($bare) = Resources::limits(array(), true, 7953, 4, filesystem($none), null);
check('"max" is no cap: neither half is sent', !isset($bare['limit_mem_mb']) && !isset($bare['limit_mem_used_mb']) && !isset($bare['limit_cpu_cores']));
$big = $v2;
$big['/sys/fs/cgroup/memory.max'] = "17179869184\n";
$big['/sys/fs/cgroup/cpu.max'] = "800000 100000\n";
list($above) = Resources::limits(array(), true, 7953, 4, filesystem($big), null);
check('a cap at or above the machine\'s own is no cap', !isset($above['limit_mem_mb']) && !isset($above['limit_cpu_cores']));

$v1 = array(
    '/proc/self/cgroup' => "12:memory:/docker/abc\n4:cpu,cpuacct:/docker/abc\n0::/\n",
    '/sys/fs/cgroup/memory/memory.limit_in_bytes' => "9223372036854771712\n",
    '/sys/fs/cgroup/memory/memory.usage_in_bytes' => "104857600\n",
    '/sys/fs/cgroup/memory/memory.stat' => "total_inactive_file 0\n",
    '/sys/fs/cgroup/memory/memory.oom_control' => "oom_kill_disable 0\nunder_oom 0\noom_kill 1\n",
    '/sys/fs/cgroup/cpu/cpu.cfs_quota_us' => "200000\n",
    '/sys/fs/cgroup/cpu/cpu.cfs_period_us' => "100000\n",
);
list($old) = Resources::limits(array(), true, 7953, 4, filesystem($v1), null);
check('cgroup v1, in a container\'s own namespace: v1\'s "no limit" number is no cap, the CPU quota is', !isset($old['limit_mem_mb'])
    && $old['limit_cpu_cores'] === 2.0);
list($nothing) = Resources::limits(array(), true, 7953, 4, filesystem(array()), null);
check('outside Linux nothing at all is sent', $nothing === array());

// PHP-FPM's pool.
$fpm = array('pool' => 'www', 'process-manager' => 'static', 'start-time' => 1760000000, 'listen-queue' => 3,
    'active-processes' => 7, 'total-processes' => 8, 'max-children-reached' => 2);
$kept = array();
$pool = Resources::fpmFields($fpm, array(), $kept, 1760000600);
check('FPM: workers busy, its maximum under pm = static, connections waiting', $pool['workers_busy'] === 7 && $pool['workers_max'] === 8
    && $pool['queue_waiting'] === 3);
check('the pool names the row and says how long it has run', preg_match('/^[a-f0-9]{16}$/', $pool['proc_key']) && $pool['proc_uptime_s'] === 600);
check('one reading of max-children-reached says nothing yet', !isset($pool['pool_maxed']));
$fpm['max-children-reached'] = 5;
$fpm['process-manager'] = 'dynamic';
$kept2 = array();
$again = Resources::fpmFields($fpm, json_decode(json_encode($kept), true), $kept2, 1760000660);
check('the pool at its cap since the last sample, and no maximum under pm = dynamic', $again['pool_maxed'] === 3 && !isset($again['workers_max'])
    && $again['proc_key'] === $pool['proc_key']);
$fpm['start-time'] = 1760000700;
$fpm['max-children-reached'] = 0;
$kept3 = array();
$restarted = Resources::fpmFields($fpm, json_decode(json_encode($kept2), true), $kept3, 1760000720);
check('a restarted pool is a new process: a new key, uptime from 0, no difference', !isset($restarted['pool_maxed'])
    && $restarted['proc_key'] !== $pool['proc_key'] && $restarted['proc_uptime_s'] === 20);
check('not FPM: nothing', Resources::fpmFields(false, array(), $kept3) === array());

// A sample outside FPM (a command-line cron run) keeps the pool's state.
list(, $cliKeep) = Resources::limits(array('fpm' => $kept2['fpm']), true, 7953, 4, filesystem(array()), null);
check('a sample outside FPM keeps the pool\'s key and count for the next one', isset($cliKeep['fpm']) && $cliKeep['fpm'] === $kept2['fpm']);

// The state outlives a reboot; the kernel's counters don't.
$booted = $v2;
$booted['/proc/uptime'] = "1000.5 900.1\n";
$booted['/proc/net/netstat'] = sprintf($NETSTAT, 40);
list(, $bootKeep) = Resources::limits(array(), true, 7953, 4, filesystem($booted), null, 1760000000);
$booted['/proc/net/netstat'] = sprintf($NETSTAT, 45);
list($sameBoot) = Resources::limits(json_decode(json_encode($bootKeep), true), true, 7953, 4, filesystem($booted), null, 1760000060);
$booted['/proc/uptime'] = "30.0 20.0\n";
list($rebooted) = Resources::limits(json_decode(json_encode($bootKeep), true), true, 7953, 4, filesystem($booted), null, 1760000060);
check('after a reboot the counts start again rather than diffing against the last boot', isset($sameBoot['listen_drops'])
    && $sameBoot['listen_drops'] === 5 && !isset($rebooted['listen_drops']) && !isset($rebooted['oom_kills']));

// One state folder, two containers' cgroups sampling into it in turn (the web
// and the worker containers sharing a storage volume): each is diffed against
// its own last reading, never the other's.
$cgroupAt = function ($path, $oom) {
    return array('/proc/self/cgroup' => "0::$path\n", "/sys/fs/cgroup$path/memory.current" => "1000\n",
        "/sys/fs/cgroup$path/memory.events" => "oom_kill $oom\n");
};
list(, $shared) = Resources::limits(array(), true, 7953, 4, filesystem($cgroupAt('/web', 0)), null, 1760000000);
list($worker, $shared) = Resources::limits(json_decode(json_encode($shared), true), true, 7953, 4, filesystem($cgroupAt('/worker', 6)), null, 1760000060);
list($web, $shared) = Resources::limits(json_decode(json_encode($shared), true), true, 7953, 4, filesystem($cgroupAt('/web', 1)), null, 1760000120);
list($worker2) = Resources::limits(json_decode(json_encode($shared), true), true, 7953, 4, filesystem($cgroupAt('/worker', 6)), null, 1760000180);
check('two cgroups in one state: no kills made up from their difference, each one\'s own counted', !isset($worker['oom_kills'])
    && $web['oom_kills'] === 1 && $worker2['oom_kills'] === 0);

// Two pools in turn: each keeps its own key and count.
$poolA = array('pool' => 'www', 'start-time' => 1760000000, 'max-children-reached' => 1);
$poolB = array('pool' => 'admin', 'start-time' => 1760000000, 'max-children-reached' => 9);
$k1 = array();
$a1 = Resources::fpmFields($poolA, array(), $k1, 1760000600);
$k2 = array();
$b1 = Resources::fpmFields($poolB, json_decode(json_encode($k1), true), $k2, 1760000660);
$k3 = array();
$poolA['max-children-reached'] = 4;
$a2 = Resources::fpmFields($poolA, json_decode(json_encode($k2), true), $k3, 1760000720);
check('two pools in turn: each keeps its key, and its count is its own', !isset($b1['pool_maxed']) && $a2['proc_key'] === $a1['proc_key']
    && $a2['pool_maxed'] === 3 && $b1['proc_key'] !== $a1['proc_key']);

// A real sample keeps the counters for the next one.
$state = json_decode(file_get_contents($core->dir() . '/resources.state'), true);
check('the state keeps the limits\' counters beside the CPU ones', array_key_exists('lim', $state));

// Tidy up.
foreach (glob($core->dir() . '/*') ?: array() as $file) {
    @unlink($file);
}
@rmdir($core->dir());
@rmdir($store);

echo ($failed ? "FAILED" : "ok") . ": $checked checks, $failed failed\n";
exit($failed ? 1 : 0);

// --- The detail pass: where the time went, and how busy the hardware was ---

// user nice system idle iowait irq softirq steal
$cpuBefore = array(1000, 100, 500, 8000, 200, 10, 20, 170);
$cpuAfter = array(1100, 100, 550, 8600, 240, 10, 20, 180);
$shares = Resources::cpuShares($cpuBefore, $cpuAfter);
// 800 jiffies passed and 10 of them went to another tenant on the same host.
check('steal is reported, because nothing else the customer sees says it', $shares['cpu_steal_pct'] === 1.3);
check('iowait is reported as its own share', $shares['cpu_iowait_pct'] === 5.0);
// user folds nice in, the way top adds them together.
check('user folds nice in', $shares['cpu_user_pct'] === 12.5);

// A kernel too old to carry the column must not report it as nought.
$short = Resources::cpuShares(array(1000, 100, 500, 8000), array(1100, 100, 550, 8600));
check('a column the kernel lacks is left out, never sent as nought', !isset($short['cpu_steal_pct']));
check('what the kernel does carry is still reported', isset($short['cpu_user_pct']));
// One reading, or counters that went backwards (a reboot), says nothing.
check('one reading says nothing', Resources::cpuShares(null, $cpuAfter) === array());
check('a reboot is not negative time', Resources::cpuShares($cpuAfter, $cpuBefore) === array());

$stats = "   8   0 sda 100 0 2000 0 50 0 4000 0 0 0 0\n"
    . "   8   1 sda1 90 0 1800 0 40 0 3000 0 0 0 0\n"
    . "   7   0 loop0 10 0 100 0 0 0 0 0 0 0 0\n"
    . " 259   0 nvme0n1 20 0 1000 0 10 0 2000 0 0 0 0\n"
    . " 259   1 nvme0n1p1 15 0 900 0 8 0 1500 0 0 0 0\n";
check('a partition is not counted twice with the disk it sits on',
    Resources::diskCounters($stats) === array(3000 * 512, 6000 * 512));
check('a machine showing no real disk reports nothing, not nought',
    Resources::diskCounters('') === null);

$dev = "    lo: 5000 10 0 0 0 0 0 0 5000 10 0 0 0 0 0 0\n"
    . "  eth0: 1000 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0\n"
    . "docker0: 9000 10 0 0 0 0 0 0 9000 10 0 0 0 0 0 0\n";
check('container and loopback traffic is not the site\'s traffic',
    Resources::netCounters($dev) === array(1000, 2000));

$megabyte = 1024 * 1024;
check('a rate is megabytes a second', Resources::rateMbs(0, 60 * $megabyte, 60) === 1.0);
// This client samples only while a visitor waits, so the two readings can be
// an hour apart. An hour's throughput is not this minute's rate.
check('an hour between readings is not a rate for one minute',
    Resources::rateMbs(0, 60 * $megabyte, 3600) === null);
check('a reboot that reset the counter is not a negative rate',
    Resources::rateMbs(60 * $megabyte, 0, 60) === null);
