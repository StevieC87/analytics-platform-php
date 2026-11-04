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

    public function __construct(?\Psr\Cache\CacheItemPoolInterface $pool = null)
    {
        $this->pool = $pool;
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
            // PSR-6 keys can't hold ":".
            $item = $this->pool->getItem('analytics_platform.' . strtr((string) $key, ':', '.'));
            $hits = ($item->isHit() ? (int) $item->get() : 0) + 1;
            $this->pool->save($item->set($hits)->expiresAfter((int) $ttl));
            return $hits;
        } catch (\Throwable $e) {
            return 0;
        }
    }
}
