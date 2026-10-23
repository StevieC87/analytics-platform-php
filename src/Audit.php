<?php
// Audit log module: who did what on your site, sent to POST /events/audit
// after the response (Security → Audit log). record('user.role_changed',
// $actor, $target, $details); the current visitor's address and visit are
// added. What goes in (names, emails) is up to you. The WordPress plugin and
// Laravel record their usual events on their own.

namespace AnalyticsPlatform;

class Audit
{
    const BATCH = 100;
    const QUEUE_MAX = 500;

    private $core;
    private $queue = array();

    public function __construct(Core $core)
    {
        $this->core = $core;
    }

    // $ip: the actor's address (default: none; Platform passes the visitor's).
    public function record($action, $actor = '', $target = '', $details = null, $ip = '')
    {
        if (!is_string($action) || $action === '' || !$this->core->isOn('audit') || count($this->queue) >= self::QUEUE_MAX) {
            return;
        }
        $this->queue[] = array(
            'at' => gmdate('Y-m-d\TH:i:s\Z'),
            'action' => substr($action, 0, 64),
            'actor' => substr((string) $actor, 0, 200),
            'target' => substr((string) $target, 0, 300),
            'details' => $details,
            'actor_ip' => (string) $ip,
            'session_id' => Platform::sessionIdFromRequest(),
        );
    }

    public function pending()
    {
        return count($this->queue) > 0;
    }

    public function flush()
    {
        $waiting = $this->queue;
        $this->queue = array();
        foreach (array_chunk($waiting, self::BATCH) as $batch) {
            $this->core->http('POST', '/events/audit', array('entries' => $batch), array(), 'body');
        }
    }
}
