<?php
// Analytics module: what only the server sees for sure (payments, sign-ups,
// plan changes), next to the browser tracker's visits. Not pageviews: the
// tracker counts those, and counting them here too would count them twice.
// track() and identify() wait in memory and are sent after the response;
// lead() waits for the answer (up to 4 seconds).

namespace AnalyticsPlatform;

class Analytics
{
    const BATCH = 100;
    const QUEUE_MAX = 500;

    private $core;
    private $events = array();
    private $identities = array();

    public function __construct(Core $core)
    {
        $this->core = $core;
    }

    // $fields: numeric_value, currency, transaction_id, coupon, value, url,
    // event_label, variant, id, timestamp, event_uid (the server events docs).
    // Returns the event_uid, or '' when not queued.
    public function track($name, array $fields = array(), $sessionId = null)
    {
        if (!is_string($name) || $name === '' || !$this->core->isOn('analytics') || count($this->events) >= self::QUEUE_MAX) {
            return '';
        }
        $event = $fields + array(
            'timestamp' => gmdate('Y-m-d\TH:i:s\Z'),
            'session_id' => $sessionId === null ? Platform::sessionIdFromRequest() : (string) $sessionId,
        );
        $event['event_name'] = substr($name, 0, 100);
        $event['event_uid'] = isset($fields['event_uid']) && $fields['event_uid'] !== '' ? (string) $fields['event_uid'] : self::uuid();
        if (isset($event['numeric_value']) && (is_int($event['numeric_value']) || is_float($event['numeric_value']))) {
            $event['numeric_value'] = (string) $event['numeric_value'];
        }
        $this->events[] = $event;
        return $event['event_uid'];
    }

    // Links the visit to your user ID (sent after the response).
    public function identify($userId, $sessionId = null)
    {
        $session = $sessionId === null ? Platform::sessionIdFromRequest() : (string) $sessionId;
        if ((string) $userId === '' || $session === '' || !$this->core->isOn('analytics')) {
            return false;
        }
        $this->identities[] = array('user_id' => (string) $userId, 'session_id' => $session);
        return true;
    }

    // $fields: email or phone, and name, status, tags, note, deal fields...
    // Returns array('status' => ..., 'lead_id' => ...), or null.
    public function lead(array $fields, $sessionId = null)
    {
        if (!$this->core->isOn('analytics')) {
            return null;
        }
        $fields += array('session_id' => $sessionId === null ? Platform::sessionIdFromRequest() : (string) $sessionId);
        $res = $this->core->http('POST', '/events/lead', $fields, array(), 'body');
        if ($res['status'] < 200 || $res['status'] >= 300) {
            return null;
        }
        $data = json_decode($res['body'], true);
        return is_array($data) ? $data : null;
    }

    public function pending()
    {
        return $this->events || $this->identities;
    }

    public function flush()
    {
        $events = $this->events;
        $identities = $this->identities;
        $this->events = array();
        $this->identities = array();
        foreach (array_chunk($events, self::BATCH) as $batch) {
            $this->core->http('POST', '/events/server-events', array('events' => $batch), array(), 'body');
        }
        foreach ($identities as $identity) {
            $this->core->http('POST', '/events/identify', $identity, array(), 'body');
        }
    }

    private static function uuid()
    {
        $bytes = random_bytes(16);
        $bytes[6] = chr((ord($bytes[6]) & 0x0f) | 0x40);
        $bytes[8] = chr((ord($bytes[8]) & 0x3f) | 0x80);
        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($bytes), 4));
    }
}
