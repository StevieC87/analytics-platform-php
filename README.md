# analytics-platform/platform (PHP)

One package for your PHP site's server, run from your analytics dashboard: a
**firewall**, **error monitoring** and **server analytics** (payments,
sign-ups, leads). PHP 7.4 or later, no dependencies. For WordPress, use the
Site Analytics plugin (`sdk/wordpress-plugin`), which is built on this.

```bash
composer require analytics-platform/platform
```

```php
$platform = new AnalyticsPlatform\Platform([
    'site_id'  => 'YOUR_SITE_ID',
    'secret'   => getenv('ANALYTICS_SITE_SECRET'), // site settings; keep it on the server
    'endpoint' => 'https://YOUR_COLLECTOR_URL',
    // 'trust_proxy' => 1,            // behind Nginx or a load balancer
    // 'trust_proxy' => 'cloudflare', // every request through Cloudflare
    // 'storage' => '/var/cache/analytics-platform', // default: the system temp dir
]);
$platform->protect(); // as early as possible, before any output
```

To protect every PHP file without touching your code, put those lines in a
file and load it with `auto_prepend_file` in `php.ini` or `.user.ini`.

## Modules

| Module | What it does | Default |
|---|---|---|
| `firewall` | Blocks addresses, known criminal networks, shared blocks and floods (Security → Firewall) | on |
| `firewall`'s attack patterns | Rules that match the *request* (its path, query string and user agent), not just the address, so an attack is turned away before your site runs — a package with a known hole stays safe until you update it. They come with the firewall's rules and are managed on the Security page (Firewall → Attack patterns); a pattern a real visitor might trip only watches until you promote it. Nothing to configure (protocol: `sdk/protocols/firewall.md`) | with the firewall |
| `proxy` | Serves the tracker and takes visits under your own domain, so ad blockers can't hide those visitors | on |
| `errors` | Uncaught exceptions and fatal errors in the Errors report | on |
| `analytics` | `track()`, `identify()` and `lead()` from your server | on |
| `audit` | `$platform->audit('user.role_changed', $actor, $target, $details)`; WordPress and Laravel record their usual events on their own | on |
| `flags` | `$platform->isEnabled('new-checkout', $user->id)` (WordPress: `site_analytics_flag('key')`) | on |
| `maintenance` | A "back soon" page while maintenance mode is on in the dashboard (WordPress: front end only, editors see the site) | on |
| `headers` | Adds the security headers you pick on the Security page; your own headers win | on |
| `forms` | Checks forms before you accept them: `$platform->checkForm()` (Laravel: the `ProtectForm` middleware) | on |
| `performance` | Response times and errors per route (Health → Server speed); name a route with `$platform->setRoute('/orders/{id}')` | on |
| `crawlers` | Which search engines and AI bots fetch your pages (Health → Crawlers). Your tracker can't see them: crawlers don't run JavaScript | on |
| `inventory` | Once a day, after a response, reports your Composer packages (`composer.lock`, not dev packages) and PHP version, so Security → Security check flags known security holes in them. Names and versions only. `'inventory' => ['root' => '/path/with/composer.lock']` when it isn't the document root's parent (protocol: `sdk/protocols/inventory.md`; WordPress: plugins, themes and core too, through WP-Cron) | on |
| `posture` | Once a day, how the server is set up: the php.ini settings that leave it open, and a walk of the web folder for code anyone can write and files that shouldn't be public (a database dump, a `.env`, a backup copy). Security → Security check says what to change, and asks your site for each of those files to see whether it really is downloadable. Reads only, and sends no file's contents. `'posture' => ['roots' => [__DIR__ . '/public']]`; Laravel: `ANALYTICS_POSTURE=true` (protocol: `sdk/protocols/posture.md`; WordPress: its own settings, admin accounts and scheduled jobs too, through WP-Cron) | off |
| `files` | File monitoring: `'files' => ['roots' => [__DIR__ . '/public']]`, then `$platform->checkFiles()` from a cron job, hourly; `$platform->checkFiles(true, true)` after a deploy accepts the files as they are (protocol: `sdk/protocols/files.md`). Changed code, backdoors and defacement show in Security → Page integrity (WordPress: automatic, through WP-Cron) | off |

Each takes `true`, `false` or its options (`'errors' => ['before_send' => ...]`).
They can also be switched off in the dashboard (Security → Settings → Server package).

## How it works

- **Nothing waits on us.** PHP keeps nothing between requests, so the
  firewall's rules and the module switches are kept in `storage` as PHP files
  that OPcache holds in memory. Everything that talks to us (fetching rules,
  sending errors and events) runs after the response has gone out (PHP-FPM).
- **Keep `storage` out of the web root.** It holds the firewall's events
  (visitor addresses and what they asked for), crawler hits and, with file
  monitoring on, a list of every path on the site. The folder inside it is
  named after your site id *and* a hash of your secret, so its address can't be
  worked out from the site id in your pages, and an `.htaccess` denying
  everything is written next to the files — but nginx ignores `.htaccess`, so a
  folder outside the web root is the only real answer. The default (the system
  temp directory) already is one.
- **Fails open.** No rules yet, or our service unreachable: requests pass.
- **Rate limit** needs a counter shared between requests: the APCu extension,
  or your own (`'counter' => function ($key, $ttl) { ... return $hits; }`).
  Without one, the rate limit is skipped and the dashboard says so.

## Bot protection

Call `$platform->loginFailed()` when a login fails (WordPress and Laravel do it
on their own). Past the site's limit the address is banned: straight away with
APCu, else on every server with the next rules (within a minute or two).
Floods are banned the same way, and so are addresses that ask for files no
visitor ever does (`/.env`, `/.git/`, backups: the dashboard sends the list),
when the firewall is in block mode.

## Server analytics and errors

```php
$platform->track('purchase', ['numeric_value' => '49.90', 'currency' => 'EUR', 'transaction_id' => $order->number]);
$platform->identify($user->id);
$platform->lead(['email' => 'ana@example.com', 'name' => 'Ana', 'status' => 'qualified']); // waits for the answer

try {
    chargeCard($order);
} catch (PaymentException $e) {
    $platform->captureException($e, null, 502);
    throw $e;
}
```

The visit is read from the `X-Analytics-Session` header (send
`window.analyticsSession.getId()` with your requests) or the
`analytics_session` cookie, which the WordPress plugin sets.

## Laravel

`composer require analytics-platform/platform` is all: package discovery adds the
middleware in front of every request, and errors Laravel reports go to the
Errors report too. Set in `.env`:

```
ANALYTICS_SITE_ID=YOUR_SITE_ID
ANALYTICS_SITE_SECRET=...
ANALYTICS_FIREWALL_ENDPOINT=https://YOUR_COLLECTOR_URL
```

In your code: `app(AnalyticsPlatform\Platform::class)->track('purchase', [...])`.
The visitor's address is `$request->ip()`, so set up Laravel's trusted proxies
if you're behind a load balancer or Cloudflare. The rate limit counts in your
cache store (not the `array` driver). Modules: `ANALYTICS_FIREWALL`,
`ANALYTICS_ERRORS`, `ANALYTICS_SERVER_EVENTS`, `ANALYTICS_INVENTORY` (`false` turns one off). To
protect only some routes, set `ANALYTICS_FIREWALL_GLOBAL=false` and add
`AnalyticsPlatform\Laravel\FirewallMiddleware` to them.

## Ad blockers

Many visitors use an ad blocker, and most blockers stop analytics. They
recognise **the address a script comes from** and **what it is called**, so a
tracker loaded from us is simply never counted.

Your site already runs on your own domain, so the package serves the tracker
and takes the visits itself. `protect()` (or Laravel's middleware) answers
those two addresses before anything else; put them in your page's tag.

```php
$proxy = $platform->proxy();
?>
<script async src="<?= $proxy->scriptUrl() ?>" data-siteid="..."
        data-domain="example.com" data-collect="<?= $proxy->collectUrl() ?>"></script>
```

- The path comes from your secret (`/3f9a2c1b/...`), so it isn't in the page
  and isn't a name any blocker lists. Pick your own with
  `'proxy' => ['prefix' => '...']`.
- Tracker files are kept in the storage folder, so a repeat visitor costs no
  request of ours; if we can't be reached, the copy already there is served
  rather than nothing.
- The visitor's address goes on as `X-Forwarded-For` (your collector needs it
  for the country, the daily visitor ID and the rate limit) and cookies never
  leave your server.
- Beacons are answered before the firewall, the crawler count and the timing,
  so your own analytics traffic doesn't appear as pages of your site.
- **WordPress does it for you**: the plugin adds a rewrite and answers through
  `px.php`, without loading WordPress at all. Settings → Site Analytics → Ad
  blockers says whether it's working.
- Switch it off with `'proxy' => false` (Laravel: `ANALYTICS_PROXY=false`), or
  in the dashboard (Security → Settings → Server package).

## Other frameworks

`$platform->firewall()->check($ip, $method, $path, $userAgent)` returns the
decision without ending the request; call `$platform->afterResponse()` once the
response has gone out.
