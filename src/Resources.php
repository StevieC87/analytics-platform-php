<?php
// Resources module (protocol in sdk/protocols/resources.md): how the machine
// is doing — CPU, load, memory, swap, disks — sampled about once a minute and
// sent to POST /events/resources every few minutes. The companion of the
// performance module: that says how the requests went, this says whether the
// box can still serve them, so the dashboard shows what you would otherwise
// run node_exporter, Prometheus and Grafana for.
//
// PHP has no process that lives between requests, so a sample is taken during
// a request (at shutdown, like the request timings) and the previous
// /proc/stat reading is kept in the state folder. That is what lets a PHP site
// report a real CPU average: the difference between two readings a minute
// apart. The cost is that **sampling needs traffic** — a site nobody visits
// for an hour reports nothing for that hour, and the CPU figure is left out
// after a long gap rather than attributed to a minute it didn't measure.
//
// Nothing is guessed. A reading this machine won't give us is left out of the
// row, never sent as a zero: the collector stores it as NULL and the dashboard
// shows "—", because "0% CPU" and "we couldn't measure CPU" are different
// statements and only one of them means healthy.

namespace AnalyticsPlatform;

class Resources
{
    // Keep in step with the collector (expresscollect/Analytics/resources.js),
    // the agent and the Node and Python packages.
    const SAMPLE_EVERY = 60;
    const SEND_EVERY = 300;
    const MAX_ROWS = 500;
    const MAX_DISKS = 20;
    // Nobody watches a sub-gigabyte partition fill up; this drops the EFI
    // partition without needing a list of paths.
    const MIN_DISK_MB = 1024;
    // Two readings closer together than this can't be divided: the counters
    // move in ticks, so the percentage would be quantisation noise.
    const MIN_CPU_SECONDS = 10;
    // ...and further apart than this, the average covers far more than the
    // minute the row is labelled with, so it is left out instead.
    const MAX_CPU_SECONDS = 300;
    const SPOOL_MAX = 1000000;

    // Real on-disk filesystems only: no tmpfs, devtmpfs, proc, sysfs or
    // squashfs (snaps), none of which are the customer's disk. overlay is
    // here so a containerised site still reports something sensible.
    private static $fstypes = array('ext2', 'ext3', 'ext4', 'xfs', 'btrfs', 'zfs', 'f2fs', 'jfs',
        'reiserfs', 'ufs', 'vfat', 'exfat', 'ntfs', 'ntfs3', 'overlay', 'apfs', 'hfs');

    private $core;
    private $options;

    // Options: server_name (default the host name).
    public function __construct(Core $core, array $options = array())
    {
        $this->core = $core;
        $this->options = $options + array('server_name' => function_exists('gethostname') ? gethostname() : '');
    }

    private static function readText($path, $limit = 65536)
    {
        if (!@is_readable($path)) {
            return '';
        }
        $text = @file_get_contents($path, false, null, 0, $limit);
        return is_string($text) ? $text : '';
    }

    // The jiffie counters from /proc/stat's first line, or null. In order:
    // user, nice, system, idle, iowait, irq, softirq, steal.
    public static function cpuFields($text)
    {
        foreach (explode("\n", (string) $text) as $line) {
            if (strncmp($line, 'cpu ', 4) !== 0) {
                continue;
            }
            $fields = array();
            foreach (preg_split('/\s+/', trim(substr($line, 4))) as $value) {
                if (!is_numeric($value)) {
                    return null;
                }
                $fields[] = (int) $value;
            }
            return count($fields) >= 4 ? $fields : null;
        }
        return null;
    }

    // (busy, total) from counters already in hand.
    public static function cpuTimesOf(array $fields)
    {
        $total = array_sum($fields);
        $idle = $fields[3] + (isset($fields[4]) ? $fields[4] : 0);
        return array($total - $idle, $total);
    }

    // Where the machine's time went between two readings, or an empty array
    // when the pair can't say. A column this kernel is too old to carry is
    // left out rather than sent as a zero. steal is the one worth surfacing:
    // time the hypervisor gave to another tenant, which no amount of tuning
    // this site will change.
    public static function cpuShares($before, $after)
    {
        if (!is_array($before) || !is_array($after)) {
            return array();
        }
        $total = array_sum($after) - array_sum($before);
        if ($total <= 0) {
            return array();
        }
        // user folds nice in, as top adds them together.
        $parts = array(
            'cpu_user_pct' => array(0, 1),
            'cpu_system_pct' => array(2),
            'cpu_iowait_pct' => array(4),
            'cpu_steal_pct' => array(7),
        );
        $out = array();
        foreach ($parts as $name => $columns) {
            $moved = 0;
            $known = true;
            foreach ($columns as $i) {
                if (!isset($before[$i]) || !isset($after[$i])) {
                    $known = false;
                    break;
                }
                $moved += $after[$i] - $before[$i];
            }
            if (!$known) {
                continue;
            }
            if ($moved < 0) {
                return array();
            }
            $out[$name] = round(min(100.0, 100.0 * $moved / $total), 1);
        }
        return $out;
    }

    // (bytes read, bytes written) since boot over the real disks, or null.
    // Partitions are skipped so they are not counted twice with the disk they
    // sit on, and loop/ram/device-mapper devices are not disks at all.
    public static function diskCounters($text)
    {
        $read = 0;
        $written = 0;
        $found = false;
        foreach (explode("\n", (string) $text) as $line) {
            $fields = preg_split('/\s+/', trim($line));
            if (count($fields) < 10) {
                continue;
            }
            $name = $fields[2];
            if (preg_match('/^(?:loop|ram|zram|sr|fd|dm-|md\d)/', $name)
                || preg_match('/^(?:(?:sd|vd|xvd|hd)[a-z]+\d+|(?:nvme\d+n\d+|mmcblk\d+)p\d+)$/', $name)) {
                continue;
            }
            if (!is_numeric($fields[5]) || !is_numeric($fields[9])) {
                continue;
            }
            // Sectors here are always 512 bytes: the unit of the interface.
            $read += (int) $fields[5] * 512;
            $written += (int) $fields[9] * 512;
            $found = true;
        }
        return $found ? array($read, $written) : null;
    }

    // (bytes in, bytes out) since boot over the real interfaces, or null.
    public static function netCounters($text)
    {
        $rx = 0;
        $tx = 0;
        $found = false;
        foreach (explode("\n", (string) $text) as $line) {
            $at = strpos($line, ':');
            if ($at === false) {
                continue;
            }
            $name = trim(substr($line, 0, $at));
            // Loopback, and the virtual ends of container and VM networking.
            if ($name === '' || preg_match('/^(?:lo|veth|docker|br-|virbr|tap|tun|vnet)/', $name)) {
                continue;
            }
            $fields = preg_split('/\s+/', trim(substr($line, $at + 1)));
            if (count($fields) < 9 || !is_numeric($fields[0]) || !is_numeric($fields[8])) {
                continue;
            }
            $rx += (int) $fields[0];
            $tx += (int) $fields[8];
            $found = true;
        }
        return $found ? array($rx, $tx) : null;
    }

    // Megabytes a second between two byte counters, or null when the pair
    // can't say: no pair, a reboot that reset them, no time, or too long a
    // gap. The gap rule matters most here: this client samples only while a
    // visitor is waiting, so two readings can be an hour apart.
    public static function rateMbs($before, $after, $seconds)
    {
        if ($before === null || $after === null) {
            return null;
        }
        if ($seconds <= 0 || $seconds > self::MAX_CPU_SECONDS) {
            return null;
        }
        $moved = $after - $before;
        if ($moved < 0) {
            return null;
        }
        return round($moved / $seconds / 1048576, 1);
    }

    // (busy, total) jiffies from /proc/stat's first line, or null. idle and
    // iowait are the machine doing nothing; everything else, steal included,
    // is time it wasn't available to us.
    public static function cpuTimes($text)
    {
        $fields = self::cpuFields($text);
        return $fields === null ? null : self::cpuTimesOf($fields);
    }

    // How busy the machine was between two readings, or null when the pair
    // can't say: no previous reading, a counter reset, or no time passed.
    public static function cpuPercent($before, $after)
    {
        if (!is_array($before) || !is_array($after)) {
            return null;
        }
        $busy = $after[0] - $before[0];
        $total = $after[1] - $before[1];
        if ($total <= 0 || $busy < 0) {
            return null;
        }
        return round(min(100.0, 100.0 * $busy / $total), 1);
    }

    // MemTotal/MemAvailable/Swap from /proc/meminfo, in whole megabytes.
    // Used is total - MemAvailable, never total - MemFree: page cache is not
    // pressure, and counting it as used makes every healthy Linux box look
    // full. A field the kernel didn't give us is left out.
    public static function memoryMb($text)
    {
        $values = array();
        foreach (explode("\n", (string) $text) as $line) {
            $parts = explode(':', $line, 2);
            if (count($parts) < 2) {
                continue;
            }
            $fields = preg_split('/\s+/', trim($parts[1]));
            if (!isset($fields[0]) || !is_numeric($fields[0])) {
                continue;
            }
            $values[$parts[0]] = (int) floor((int) $fields[0] / 1024);
        }
        $out = array();
        if (isset($values['MemTotal'])) {
            $out['mem_total_mb'] = $values['MemTotal'];
            if (isset($values['MemAvailable'])) {
                $out['mem_used_mb'] = max(0, $values['MemTotal'] - $values['MemAvailable']);
            }
        }
        if (isset($values['SwapTotal'])) {
            $out['swap_total_mb'] = $values['SwapTotal'];
            if (isset($values['SwapFree'])) {
                $out['swap_used_mb'] = max(0, $values['SwapTotal'] - $values['SwapFree']);
            }
        }
        return $out;
    }

    // One mount per device, under its shortest mount point, so a bind mount
    // isn't reported as a second disk. Without /proc/mounts the only
    // filesystem we can name without guessing is the site's own folder.
    //
    // A mount point has to be a **directory**. Docker bind-mounts single
    // files, so a container's /proc/mounts lists /etc/hosts, /etc/hostname
    // and /etc/resolv.conf on the host's own device — and those paths are
    // short, so without this they win the shortest-path race against the
    // real mount and the panel names a file as one of the site's disks.
    //
    // The directory test is per-device and advisory: open_basedir makes
    // is_dir() false for paths a shared host won't show us, and reporting no
    // disks at all would be worse than reporting an odd mount point, so a
    // device whose mounts we cannot confirm keeps its shortest one.
    public static function mountPoints($mountsText, $fallback = '/', $isDir = null)
    {
        if (trim((string) $mountsText) === '') {
            return array($fallback);
        }
        $isDir = $isDir ?: 'is_dir';
        $usable = is_callable($isDir);
        $dirs = array();
        $any = array();
        foreach (explode("\n", (string) $mountsText) as $line) {
            $fields = preg_split('/\s+/', trim($line));
            if (count($fields) < 3) {
                continue;
            }
            $device = $fields[0];
            $mount = str_replace('\\040', ' ', $fields[1]);
            if (!in_array($fields[2], self::$fstypes, true) || strpos($mount, '/') !== 0) {
                continue;
            }
            if (!isset($any[$device]) || strlen($mount) < strlen($any[$device])) {
                $any[$device] = $mount;
            }
            if ($usable && @call_user_func($isDir, $mount)
                && (!isset($dirs[$device]) || strlen($mount) < strlen($dirs[$device]))) {
                $dirs[$device] = $mount;
            }
        }
        $points = array();
        foreach ($any as $device => $mount) {
            $points[] = isset($dirs[$device]) ? $dirs[$device] : $mount;
        }
        $points = array_values(array_unique($points));
        sort($points);
        return $points;
    }

    // disk_total_space/disk_free_space are what PHP has, and they are df's
    // "size" and "available" — so used is size minus available, and total is
    // the size. Unlike the agent this cannot see the blocks reserved for
    // root, so used/total can read a few points under df's Use% on a disk
    // that has a reserve.
    public static function diskRows(array $points, $total = null, $free = null)
    {
        $total = $total ?: 'disk_total_space';
        $free = $free ?: 'disk_free_space';
        // Shared hosts commonly put these two in disable_functions, where PHP
        // 8 raises an Error that @ does not suppress — so the disk figures
        // have to be skipped rather than attempted. is_callable, not
        // function_exists, because the tests pass closures.
        if (!is_callable($total) || !is_callable($free)) {
            return array();
        }
        $rows = array();
        // One filesystem can sit behind two devices the kernel calls
        // different: in a container / is the overlay and the app's folder is
        // a bind of the host disk the overlay's upperdir lives on, so both
        // report the same size and the same free space down to the byte. No
        // device- or st_dev-based rule separates them, so the sizes are what
        // gives it away — a second mount matching an earlier one exactly is
        // the same storage seen twice.
        //
        // Raw bytes, not the rounded megabytes, so two disks that merely
        // round alike stay apart. Two genuinely separate filesystems of
        // identical size and identical free bytes do exist — a pair of
        // freshly formatted volumes nothing has written to — and one of them
        // is dropped until something is written to either. Both are empty, so
        // the fullness alert this feeds loses nothing.
        $seen = array();
        foreach ($points as $mount) {
            $size = @call_user_func($total, $mount);
            $available = @call_user_func($free, $mount);
            if (!is_numeric($size) || !is_numeric($available) || $size <= 0) {
                continue;
            }
            $row = array(
                'mount' => $mount,
                'total_mb' => (int) floor($size / 1048576),
                'used_mb' => (int) floor(max(0, $size - $available) / 1048576),
            );
            if ($row['total_mb'] < self::MIN_DISK_MB) {
                continue;
            }
            // $points arrives sorted, so the shortest path wins the collision.
            $key = $size . ':' . $available;
            if (isset($seen[$key])) {
                continue;
            }
            $seen[$key] = true;
            $rows[] = $row;
            if (count($rows) >= self::MAX_DISKS) {
                break;
            }
        }
        return $rows;
    }

    public static function hostUptime($text)
    {
        $fields = preg_split('/\s+/', trim((string) $text));
        return isset($fields[0]) && is_numeric($fields[0]) ? (int) $fields[0] : null;
    }

    // Is a sample due? PHP only runs while a request does, so "about once a
    // minute" means "on the first request after a minute has passed".
    public function due()
    {
        $file = $this->core->dir() . '/resources.state';
        clearstatcache(true, $file);
        return !is_file($file) || filemtime($file) <= time() - self::SAMPLE_EVERY;
    }

    // Takes a sample if one is due, appends it to the spool, and sends the
    // spool when that is due too. Platform calls this at shutdown.
    public function flush($force = false)
    {
        if (!$this->core->isOn('resources') || !$this->core->ensureDir()) {
            return;
        }
        if ($force || $this->due()) {
            $row = $this->sample();
            if ($row) {
                $this->spool($row);
            }
        }
        $this->send($force);
    }

    // One sample, covering the time since the last one. The previous
    // /proc/stat reading and the time of it live in resources.state, which is
    // the only way a language with no daemon can measure CPU at all.
    public function sample($now = null)
    {
        $now = $now === null ? time() : (int) $now;
        $file = $this->core->dir() . '/resources.state';
        $state = json_decode(self::readText($file, 4096), true);
        $fields = self::cpuFields(self::readText('/proc/stat'));
        $disk = self::diskCounters(self::readText('/proc/diskstats'));
        $net = self::netCounters(self::readText('/proc/net/dev'));
        $cpu = $fields === null ? null : self::cpuTimesOf($fields);
        // A state file written before the breakdown existed holds the two
        // (busy, total) figures rather than the counters; it is not a reading
        // this code can use, so the first sample after an upgrade is skipped
        // rather than measured against the wrong numbers.
        $before = is_array($state) && isset($state['cpu']) && is_array($state['cpu']) && count($state['cpu']) >= 4
            ? array_values($state['cpu']) : null;
        $previous = $before === null ? null : self::cpuTimesOf($before);
        $lastDisk = is_array($state) && isset($state['disk']) && is_array($state['disk']) && count($state['disk']) === 2
            ? array_values($state['disk']) : null;
        $lastNet = is_array($state) && isset($state['net']) && is_array($state['net']) && count($state['net']) === 2
            ? array_values($state['net']) : null;
        $since = is_array($state) && isset($state['at']) ? (int) $state['at'] : null;
        // The minute the interval started in, not the one it ended in.
        $minute = $since !== null ? $since : $now;
        $row = array('minute' => gmdate('Y-m-d\TH:i:s\Z', (int) (floor($minute / 60) * 60)));
        $elapsed = $since === null ? null : $now - $since;
        $percent = self::cpuPercent($previous, $cpu);
        // Left out after a long gap: the average would cover far more than the
        // minute this row is labelled with, which no reader could tell.
        $usable = $elapsed !== null && $elapsed >= self::MIN_CPU_SECONDS && $elapsed <= self::MAX_CPU_SECONDS;
        if ($percent !== null && $usable) {
            $row['cpu_pct'] = $percent;
        }
        // The breakdown and the rates cover the same interval as cpu_pct, so
        // they live or die with it: an hour's average must not be labelled as
        // one minute.
        if ($usable) {
            foreach (self::cpuShares($before, $fields) as $name => $value) {
                $row[$name] = $value;
            }
            $rates = array();
            if ($lastDisk !== null && $disk !== null) {
                $rates['disk_read_mbs'] = self::rateMbs($lastDisk[0], $disk[0], $elapsed);
                $rates['disk_write_mbs'] = self::rateMbs($lastDisk[1], $disk[1], $elapsed);
            }
            if ($lastNet !== null && $net !== null) {
                $rates['net_rx_mbs'] = self::rateMbs($lastNet[0], $net[0], $elapsed);
                $rates['net_tx_mbs'] = self::rateMbs($lastNet[1], $net[1], $elapsed);
            }
            foreach ($rates as $name => $value) {
                if ($value !== null) {
                    $row[$name] = $value;
                }
            }
        }
        if ($fields !== null) {
            @file_put_contents($file, json_encode(array(
                'cpu' => $fields,
                'disk' => $disk,
                'net' => $net,
                'at' => $now,
            )), LOCK_EX);
            @chmod($file, 0600);
        } else {
            @touch($file);
        }
        $cores = self::cores();
        if ($cores) {
            $row['cpu_cores'] = $cores;
        }
        if (function_exists('sys_getloadavg')) {
            $load = @sys_getloadavg();
            if (is_array($load) && count($load) === 3) {
                $row['load1'] = round((float) $load[0], 2);
                $row['load5'] = round((float) $load[1], 2);
                $row['load15'] = round((float) $load[2], 2);
            }
        }
        $row += self::memoryMb(self::readText('/proc/meminfo'));
        $disks = self::diskRows(self::mountPoints(self::readText('/proc/mounts'), self::siteRoot()));
        if ($disks) {
            $row['disks'] = $disks;
        }
        // This package runs inside the application, so unlike the agent it can
        // honestly report the application's own memory.
        if (function_exists('memory_get_peak_usage')) {
            $row['proc_rss_mb'] = max(1, (int) floor(memory_get_peak_usage(true) / 1048576));
        }
        $uptime = self::hostUptime(self::readText('/proc/uptime'));
        if ($uptime !== null) {
            $row['host_uptime_s'] = $uptime;
        }
        // Nothing but a minute label is not a sample.
        return count($row) > 1 ? $row : null;
    }

    private static function cores()
    {
        $text = self::readText('/proc/cpuinfo', 1048576);
        if ($text !== '') {
            $count = preg_match_all('/^processor\s*:/m', $text);
            if ($count) {
                return $count;
            }
        }
        return 0;
    }

    private static function siteRoot()
    {
        $root = isset($_SERVER['DOCUMENT_ROOT']) ? (string) $_SERVER['DOCUMENT_ROOT'] : '';
        return $root !== '' ? $root : '/';
    }

    private function spool(array $row)
    {
        $this->core->append('resources', $row, self::SPOOL_MAX);
    }

    // Sends the spooled samples, every SEND_EVERY seconds.
    private function send($force = false)
    {
        $this->core->drain('resources', self::SEND_EVERY, $force, function (array $samples) {
            $rows = array();
            foreach ($samples as $row) {
                if (isset($row['minute'])) {
                    $rows[$row['minute']] = $row;
                }
            }
            ksort($rows);
            $rows = array_slice(array_values($rows), -self::MAX_ROWS);
            if ($rows) {
                $this->core->post('resources', '/events/resources', array(
                    'site_id' => (string) $this->core->opt('site_id'),
                    'server_name' => substr((string) $this->options['server_name'], 0, 100),
                    'runtime' => 'PHP ' . PHP_VERSION,
                    'rows' => $rows,
                ), 'bearer');
            }
        });
    }
}
