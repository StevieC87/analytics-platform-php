<?php
// The firewall's rate limit counter for Symfony: APCu when the server has it,
// else the app's cache (cache.app), as Laravel's counts in its cache store.
// Given to the Platform as its 'counter' option (README: "Symfony").
//
// A cache pool can't add one atomically: two requests at the same moment can
// read the same count and both write it plus one. So under a burst it counts
// low and a flood is stopped a little later than its limit; one address
// asking one request at a time is counted exactly. With APCu it is exact.

namespace AnalyticsPlatform\Symfony;

class CacheCounter
{
    private $pool;
    private $logger;
    private $warned = false;

    public function __construct(?\Psr\Cache\CacheItemPoolInterface $pool = null, ?\Psr\Log\LoggerInterface $logger = null)
    {
        $this->pool = $pool;
        $this->logger = $logger;
    }

    // The hit count after adding one, for a key that lasts $ttl seconds.
    public function __invoke($key, $ttl)
    {
        if (function_exists('apcu_enabled') && apcu_enabled()) {
            apcu_add($key, 0, $ttl);
            return (int) apcu_inc($key);
        }
        if (!$this->pool) {
            return 0;
        }
        try {
            // Hashed: PSR-6 keys can't hold ":" or "/", and an IPv6 visitor's
            // key holds both ("2001:db8::/64"), so as it was every IPv6
            // address was counted 0 and never limited.
            $item = $this->pool->getItem('analytics_platform.' . sha1((string) $key));
            $hits = ($item->isHit() ? (int) $item->get() : 0) + 1;
            $this->pool->save($item->set($hits)->expiresAfter((int) $ttl));
            return $hits;
        } catch (\Throwable $e) {
            // Counted as 0, so the request isn't refused for our fault; said
            // once per process, so it isn't mistaken for limits that work.
            if (!$this->warned) {
                $this->warned = true;
                $message = 'analytics-platform: the rate limit counter failed, so the rate and page limits are not counted: ' . $e->getMessage();
                if ($this->logger) {
                    $this->logger->warning($message, array('exception' => $e));
                } else {
                    error_log($message);
                }
            }
            return 0;
        }
    }
}
