# analytics-platform/platform (PHP)

One package for your PHP site's server, run from your analytics dashboard: a
**firewall**, **error monitoring** and **server analytics** (payments,
sign-ups, leads). PHP 7.4 or later, no dependencies. For WordPress, use the
Site Analytics plugin (`sdk/wordpress-plugin`), which is built on this.

```bash
composer require analytics-platform/platform
```

### The quick way: one line

Put your keys in the server's environment, or in the `.env` in your project's
folder (the one holding `vendor/`):

```bash
ANALYTICS_SITE_ID=YOUR_SITE_ID
ANALYTICS_SITE_SECRET=YOUR_SITE_SECRET
ANALYTICS_ENDPOINT=https://YOUR_COLLECTOR_URL
```

Then have PHP run the package's start file before every script, in `php.ini`,
`.user.ini` or `.htaccess` (`php_value auto_prepend_file ...`):

```ini
auto_prepend_file = /path/to/your/site/vendor/analytics-platform/platform/start.php
```

or make it the first line of the script every request goes through:

```php
require __DIR__ . '/vendor/analytics-platform/platform/start.php';
```

That's all: the firewall, errors and the rest run on every request, before
your code. `analytics_platform()` is the platform, for `track()`,
`captureException()` and the rest. The server's environment wins over `.env`,
only the `ANALYTICS_*` lines of `.env` are read, and they're never written
into the environment. Behind a load balancer or Cloudflare, add
`ANALYTICS_TRUST_PROXY=1` or `ANALYTICS_TRUST_PROXY=cloudflare` (see below).
On the command line nothing runs until you call `analytics_platform()`.
Laravel and Symfony have their own setup below.

### Setting it up in code instead

For options in code. Each of `site_id`, `secret`, `endpoint`, `server_name`
and `trust_proxy` left out is read from the `ANALYTICS_*` environment
variables above (`ANALYTICS_SERVER_NAME`, `ANALYTICS_TRUST_PROXY`), as is the
endpoint's older name, `ANALYTICS_FIREWALL_ENDPOINT`.

```php
$platform = new AnalyticsPlatform\Platform([
    'site_id'  => 'YOUR_SITE_ID',
    'secret'   => getenv('ANALYTICS_SITE_SECRET'), // site settings; keep it on the server
    'endpoint' => 'https://YOUR_COLLECTOR_URL',
    // 'trust_proxy' => 1,            // behind Nginx or a load balancer
    // 'trust_proxy' => 'cloudflare', // every request through Cloudflare (CF-Connecting-IP is
    //                                // believed only from Cloudflare's own addresses)
    // 'storage' => '/var/cache/analytics-platform', // default: the system temp dir
]);
$platform->protect(); // as early as possible, before any output
```

**`trust_proxy` counts the proxies that add to `X-Forwarded-For`**, from the
right; the hop it lands on is the visitor. A port on a hop
(`203.0.113.5:54321`, `[2001:db8::1]:443`, as Azure's load balancers send)
is dropped, and a hop that isn't an address gives the connection's address
instead, so the request is still checked. If your web server already puts the
visitor in `REMOTE_ADDR` — Apache's `mod_remoteip`, nginx's `real_ip` in front
of PHP-FPM, LiteSpeed's "Use Client IP in Header", Cloudflare's own module —
leave `trust_proxy` at 0: `REMOTE_ADDR` is then the visitor, and `mod_remoteip`
also takes the entries it used out of the header, so counting them again would
read one the visitor wrote. PHP can't tell that from the request, so it is
yours to set right. Laravel and Symfony don't use `trust_proxy` at all: their
own trusted proxies decide (`$request->ip()`, `getClientIp()`).

## Modules

| Module | What it does | Default |
|---|---|---|
| `firewall` | Blocks addresses, known criminal networks, shared blocks and floods (Security → Firewall) | on |
| `firewall`'s attack patterns | Rules that match the *request* (its path, query string and user agent), not just the address, so an attack is turned away before your site runs — a package with a known hole stays safe until you update it. They come with the firewall's rules and are managed on the Security page (Firewall → Attack patterns); a pattern a real visitor might trip only watches until you promote it. Nothing to configure (protocol: `sdk/protocols/firewall.md`) | with the firewall |
| `proxy` | Serves the tracker and takes visits under your own domain, so ad blockers can't hide those visitors | on |
| `errors` | Uncaught exceptions and fatal errors in the Errors report | on |
| `analytics` | `track()`, `identify()` and `lead()` from your server | on |
| `audit` | `$platform->audit('user.role_changed', $actor, $target, $details)`; WordPress, Laravel and Symfony record their usual events on their own | on |
| `flags` | `$platform->isEnabled('new-checkout', $user->id)` (WordPress: `site_analytics_flag('key')`) | on |
| `maintenance` | A "back soon" page while maintenance mode is on in the dashboard (WordPress: front end only, editors see the site) | on |
| `headers` | Adds the security headers you pick on the Security page; your own headers win | on |
| `forms` | Checks forms before you accept them: `$platform->checkForm()` (Laravel: the `ProtectForm` middleware) | on |
| `performance` | Response times and errors per route (Health → Server speed); name a route with `$platform->setRoute('/orders/{id}')` | on |
| `queries` | With `performance`: every database query's time per route (Health → Server speed → Queries), its values replaced by `?` before anything is counted. Laravel: automatic; Symfony: `QueryMiddleware`; plain PHP: `TimedPdo`, `TimedClickHouse`; MongoDB: automatic with the `mongodb` extension; Redis: automatic in Laravel, `TimedRedis`/`TimedPredis`; WordPress: automatic (see "Database queries") | on |
| `calls` | With `performance`: how long each route waited on other services, by the host it called (Health → Server speed → Calls). Laravel's `Http` client: automatic; Symfony: `HttpClientBreadcrumbs`; Guzzle: `guzzleMiddleware()`; WordPress: automatic (see "Outgoing calls") | on |
| `queues` | With `performance`: each job queue's backlog once a minute, and the jobs added and finished (Health → Server speed → Jobs). Laravel: automatic in `queue:work` (see "Job queues") | on |
| `crawlers` | Which search engines and AI bots fetch your pages (Off-site → Crawlers). Your tracker can't see them: crawlers don't run JavaScript | on |
| `inventory` | Once a day, after a response, reports your Composer packages (`composer.lock`, not dev packages) and PHP version, so Security → Security check flags known security holes in them. Names and versions only. `'inventory' => ['root' => '/path/with/composer.lock']` when it isn't the document root's parent (protocol: `sdk/protocols/inventory.md`; WordPress: plugins, themes and core too, through WP-Cron) | on |
| `posture` | Once a day, how the server is set up: the php.ini settings that leave it open, and a walk of the web folder for code anyone can write and files that shouldn't be public (a database dump, a `.env`, a backup copy). Security → Security check says what to change, and asks your site for each of those files to see whether it really is downloadable. Reads only, and sends no file's contents. `'posture' => ['roots' => [__DIR__ . '/public']]`; Laravel: `ANALYTICS_POSTURE=true` (protocol: `sdk/protocols/posture.md`; WordPress: its own settings, admin accounts and scheduled jobs too, through WP-Cron) | off |
| `files` | File monitoring: `'files' => ['roots' => [__DIR__ . '/public']]`, then `$platform->checkFiles()` from a cron job, hourly; `$platform->checkFiles(true, true)` after a deploy accepts the files as they are (protocol: `sdk/protocols/files.md`). Changed code, backdoors and defacement show in Security → Page integrity (WordPress: automatic, through WP-Cron) | off |

Each takes `true`, `false` or its options (`'errors' => ['before_send' => ...]`).
They can also be switched off in the dashboard (Security → Server package).

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
  Without one, the rate limit is skipped and the dashboard says so. The rate
  limit, failed logins and bans here count an IPv6 address by its /64 (one
  machine usually holds the whole /64, so rotating within it doesn't reset
  the count) and `::ffff:a.b.c.d` as `a.b.c.d`. Static files (`.css`, `.js`,
  images, fonts...) aren't counted, since a page asks for dozens; one that
  answers an error (a flood of made-up `/x.css` reaching PHP) is counted
  after the response.
- **One deadline after the response.** Everything sent after a response shares
  5 seconds: a collector that doesn't answer costs a PHP worker that, not one
  timeout per module, and what wasn't sent waits on disk for a later request.
  A batch is removed from disk only once it was sent, so a request killed
  while sending leaves it for the next.

## Bot protection

Call `$platform->loginFailed()` when a login fails (WordPress, Laravel and
Symfony do it on their own). Past the site's limit the address is banned: straight away with
APCu, else on every server with the next rules (within a minute or two).
Floods are banned the same way, and so are addresses that ask for files no
visitor ever does (`/.env`, `/.git/`, backups: the dashboard sends the list),
when the firewall is in block mode.

## Browser check

On paid plans, when you turn on flood protection's browser check in the
dashboard, a visitor's first page each day is a small page that sets a cookie
with JavaScript and reloads into your site (a blink, once a day per address).
Nothing to configure: it comes with the firewall's rules, in every mode.

- **What it stops:** cheap floods — scripts and bots that fetch your pages
  without running JavaScript.
- **What it doesn't:** a real (or headless) browser, which passes it like a
  visitor does; attacks on forms, APIs or logins, which aren't page loads.
- **A speed bump, not a lock:** it stops scripts that don't run JavaScript. A
  bot written for this product can read the pass from the page, which is why
  the pass is bound to the visitor's address and the day.
- **Only page loads are checked:** `GET` and `HEAD` that ask for `text/html`.
  Never a `POST` (forms, webhooks, payment callbacks), never an API or
  `fetch()` call, curl or a feed reader, never the paths the dashboard skips
  (`/api/`, `/wp-json/` …), your allowed addresses, the AI crawlers that bring
  visits, or the search engines' published addresses.
- **The cookie** `__sg_pass` holds a day number and a signature of the
  visitor's address (an IPv6 address's /64) made with your site secret, lasts
  a day and is sent only to your site. It is strictly necessary for security,
  identifies no one and isn't used for analytics, so it needs no consent.
- The page has its own `Content-Security-Policy`, replacing yours for that one
  response. A policy added by your web server (nginx, Apache) is added on top
  and can block it: leave that header to PHP or allow the page's nonce. In
  Symfony the package puts its policy back after every other response
  listener (NelmioSecurityBundle's too). In Laravel, put `FirewallMiddleware`
  outside any middleware that sets `Content-Security-Policy`, or that one
  replaces the page's and no visitor gets past it.
- Pages your server answers from a cache before PHP runs aren't checked.
- `on_block` isn't called for it: the page has to be the package's to set the
  pass. Elsewhere, `check()` returns `rule` `challenge` with status 503, and
  `$platform->firewall()->challengePage($ip, $method)` gives the status,
  headers and body to answer with.

## Server analytics and errors

```php
$platform->track('purchase', ['numeric_value' => '49.90', 'currency' => 'EUR', 'transaction_id' => $order->number]);
$platform->identify($user->id, null, ['plan' => 'pro', 'seats' => 5, 'trial' => false]); // traits are optional
$platform->lead(['email' => 'ana@example.com', 'name' => 'Ana', 'status' => 'qualified']); // waits for the answer

try {
    chargeCard($order);
} catch (PaymentException $e) {
    $platform->captureException($e, null, 502);
    throw $e;
}
```

`identify()` takes optional user traits as its third argument (the second is
the session ID; `null` reads it from the request): name to text, number or
`true`/`false`. Lists, objects and other values are left out. The collector
does the rest: names are lowercased with spaces and dashes as `_` (up to 40
letters, digits and `_`), text is cut at 200 characters, values that look like
an email address are dropped, and at most 20 are kept.

The visit is read from the `X-Analytics-Session` header (send
`window.analyticsSession.getId()` with your requests) or the
`analytics_session` cookie, which the WordPress plugin sets. An error carries
the route `setRoute()` named. One exception is sent once however often it is
captured, and a batch the collector couldn't take is kept on disk and sent by
a later request; each error keeps the time it happened.

An error also shows the steps before it in its request or job. Add your own
with `$platform->addBreadcrumb('Order saved')`. In Laravel, calls made with its
`Http` client are recorded on their own, with their address (no query string)
and status; in Symfony, its HttpClient's (`HttpClientBreadcrumbs`); with
Guzzle, its client's once you add `guzzleMiddleware()` (see "Outgoing
calls"). Other calls plain PHP can't see, so there it's only your own steps.
To send none, unset `$event['breadcrumbs']` in `before_send`.

Background jobs (a worker, a cron script):

```php
$platform->job('send-receipts', function () { /* ... */ });
```

Their errors carry the job's name as the route, a job that throws is sent
(status 500) and thrown on, each run is timed (Server speed → Jobs), and on
the command line errors are sent after every job. Several services on one
site: `'server_name' => 'worker'` in the options. Health → All systems lists
each by that name; PHP checks in only while it serves requests, so a quiet
site is never called down (`sdk/protocols/checkin.md`).

## Database queries

Every query is timed, its values replaced by `?` (`SELECT * FROM users WHERE id = ?`;
bound parameters are never read), and counted under the request it ran in, so
Server speed shows how much of a route's time was the database and which query.
A queue job's queries are its own; one outside any request or job is `(background)`.
Protocol: `sdk/protocols/queries.md`. It rides on the `performance` module and its
dashboard switch; `'queries' => false` keeps Server speed without it.

- **Laravel:** automatic (`QueryExecuted`, what `DB::listen` hears). Laravel
  announces no failed query, so a failure is counted when its `QueryException`
  is reported (with no time); one you catch and don't report isn't.
  `ANALYTICS_QUERIES=false` turns it off.
- **Symfony:** the Doctrine middleware, below.
- **Plain PHP:** `new AnalyticsPlatform\TimedPdo($dsn, $user, $password)` where you
  had `new PDO(...)`. `exec()`, `query()` and prepared statements' `execute()` are
  timed; prepared statements aren't on a persistent connection or with a statement
  class of your own. Your own hook for anything else:
  `$platform->recordQuery('postgresql', $sql, $ms, $failed)`.
- **ClickHouse** (`smi2/phpclickhouse`): its client has no hook a query passes
  through, so put the timer in front of the one you make:
  `$db = new AnalyticsPlatform\TimedClickHouse(new ClickHouseDB\Client($config));`.
  `select()`, `write()`, `insert()`, `insertAssocBulk()`, `selectWithParams()`
  and `writeWithParams()` are timed until they answer, `selectAsync()` ones once
  `executeAsync()` has run them; everything else goes straight through. A select
  the server refused counts as failed, though the library only throws when you
  read it, and an insert is counted as `INSERT INTO events (site, email) VALUES (?)`,
  its rows never read. Code that type-hints `ClickHouseDB\Client` can't take the
  stand-in: time those with `recordQuery('clickhouse', ...)`. A `TimedPdo` on a
  ClickHouse PDO driver is named `clickhouse` too.
- **MongoDB:** with the `mongodb` extension loaded, a command subscriber is added on
  its own (`find users {"email":"?"}`); Laravel's mongodb connections are left to it.
- **WordPress:** the plugin writes `wp-content/db.php` on activation, when there is
  none and the folder can be written, and removes it on deactivation. Otherwise it
  reads WordPress's `SAVEQUERIES` log at the end of the request, which misses the
  queries before plugins load and counts no failures.
- **Redis:** each command as its command and first key's shape only
  (`GET user:?:cart`), never an argument or value; blocking ones (`BLPOP`, `XREAD`
  with a block) aren't timed, nor are the package's own queue readings.
  Laravel: automatic (its `CommandExecuted`, with Redis events turned on for you);
  a failure is seen from Laravel 12 (`CommandFailed`, no time), and not at all for
  an error reply on phpredis, which answers `false`. Predis' `pipeline()` and
  `transaction()` are one `PIPELINE`/`MULTI` call there; phpredis' bypass Laravel's
  events, so their commands aren't seen. Plain PHP: `new
  AnalyticsPlatform\TimedRedis(new \Redis())` (phpredis, `\RedisCluster` too) or
  `new AnalyticsPlatform\TimedPredis(new Predis\Client(...))`; `multi()`/`pipeline()`
  to `exec()`/`execute()` is one `MULTI SET cart:?` call. Code that type-hints the
  client can't take the stand-in. WordPress: none (an object-cache drop-in has no
  command hook).
- **Workers** serving many requests from one process: Octane and the Symfony
  subscriber start each request's queries afresh on their own; elsewhere call
  `$platform->beginRequest()` as each request starts.

A request's queries are written down with its own timing, so they are always
filed under the route Server speed filed the request under, `(other)` included
on a minute with more routes than it keeps.

## Outgoing calls

Health → Server speed → Calls shows how long each route waited on other
services — a payment provider, an email API, your own microservices — by the
host it called (`api.stripe.com`), and how many of those calls failed. Through
the hooks the error trail already uses:

- **Laravel:** automatic, from its `Http` client's own events (`RequestSending`
  to `ResponseReceived` or `ConnectionFailed`). Laravel announces the answer
  once its body is read, so the time includes the body. `ANALYTICS_CALLS=false`
  turns it off.
- **Symfony:** `HttpClientBreadcrumbs` (see "Symfony"), timed to the first
  chunk: when the headers arrive.
- **Guzzle** (plain PHP, or a client you build yourself), timed to its headers
  through its `on_headers` option (yours still runs):

  ```php
  $stack = GuzzleHttp\HandlerStack::create();
  $stack->push($platform->guzzleMiddleware());
  $client = new GuzzleHttp\Client(['handler' => $stack]);
  ```

  Not for Laravel's `Http` client, which is timed on its own: both would count
  each call twice.
- **WordPress:** automatic, from `pre_http_request` to `http_api_debug`.
  WordPress reads the whole answer before it says so, so the time includes the
  body. A call that doesn't wait for its answer (`blocking => false`) isn't timed.
- Your own hook for anything else: `$platform->recordCall('POST', $url, $ms, $status)`
  (`$status` 0 when no answer came).

- **Only the host is sent.** A call's path, query string, headers and body
  never leave your server: paths carry IDs and keys.
- A call that got no answer, or a 5xx, is a failed one; a 4xx is the other
  side's answer, not a failure. A call your code cancels isn't counted.
- Calls are filed as queries are: under the request, the `job()`, or `JOB
  (background)`. The package's own calls to us are left out.
- They ride on Server speed's switch; `'calls' => false` leaves them out.
  Protocol: `sdk/protocols/calls.md`.

## Job queues

Health → Server speed → Jobs shows each queue's backlog once a minute: jobs
waiting, running, delayed and failed, how long the oldest has waited, and jobs
added against jobs finished — so a queue falling behind shows before the
emails go out an hour late. Laravel, nothing to set up:

- Every process counts the jobs it adds (`JobQueued`); `queue:work` counts the
  ones it finishes (`JobProcessed`, unless the job was released to run again,
  and `JobFailed`, which comes once a job has failed for good).
- PHP has no loop of its own between requests, so `queue:work` reads its
  queues between jobs (the `Looping` event), at most once a minute:
  `Queue::size()`, or where your Laravel's queue has them `pendingSize()`,
  `delayedSize()`, `reservedSize()` and `creationTimeOfOldestPendingJob()`;
  failed from the failed-job store's `count()`. Without `pendingSize()`,
  waiting is `size()`, which also counts delayed and running jobs, and what
  the queue can't say is left out. No worker running, no reading: a gap, not a
  zero. `queue:work --once` and `queue:listen` don't loop, so they read nothing.
- The queues it reads are the ones the worker processes; more with
  `ANALYTICS_WATCH_QUEUES=redis:emails,default` (`connection:queue`, or a queue
  on the default connection).
- The broker is named by host, port and database (`cache.internal:6379/0`),
  from the connection's settings; never a user name or password.
- Readings and counts are kept on disk and sent one finished minute at a time.
  Several workers reading one queue is fine: the dashboard takes the largest
  reading, never the sum.
- They ride on Server speed's switch; `ANALYTICS_QUEUES=false` (`'queues' =>
  false`) leaves them out. Protocol: `sdk/protocols/queues.md`.

## Server resources and limits

About once a minute, from a request (PHP has no process between requests), the
`resources` module samples the machine — CPU, load, memory, swap, disks,
throughput — and how close the site is to a wall, which on a container or a
busy pool is rarely the machine (Health → Server speed):

- **Its container's caps:** the memory cap and the working set that counts
  against it (`memory.current` less inactive page cache, as Docker shows it),
  the CPU cap in cores and how often it throttled the site, and processes the
  kernel killed for memory, from the cgroup (v1 or v2). A cap that isn't one
  (none set, or at or above the machine's own) is left out.
- **PHP-FPM's pool**, from `fpm_get_status()`: workers busy, connections
  waiting for one, and how often the pool wanted another worker and was at
  `pm.max_children`; its maximum only under `pm = static`, where every child is
  the maximum. The pool also names the row and says how long it has run, so an
  FPM restart shows.
- **The machine:** how long tasks waited for CPU, memory and disk
  (`/proc/pressure`), connections refused before PHP saw them (the listen
  queue overflowing), and how full the connection-tracking table is.
- Counts (kills, the pool at its cap, refused connections) are differences
  between two samples, kept in `storage`, and keep their whole difference after
  a quiet hour; after a reboot they start again. Nothing this machine won't say is sent as a zero. No open
  files and no requests in progress: each request is a process of its own,
  so the pool's figures are the ones that say it.

## Laravel

`composer require analytics-platform/platform` is all: package discovery adds the
middleware in front of every request, and errors Laravel reports go to the
Errors report too. Set in `.env`:

```
ANALYTICS_SITE_ID=YOUR_SITE_ID
ANALYTICS_SITE_SECRET=...
ANALYTICS_ENDPOINT=https://YOUR_COLLECTOR_URL
```

(`ANALYTICS_FIREWALL_ENDPOINT`, the endpoint's older name, still works.)
In your code: `app(AnalyticsPlatform\Platform::class)->track('purchase', [...])`.
The visitor's address is `$request->ip()`, so set up Laravel's trusted proxies
if you're behind a load balancer or Cloudflare. The rate limit counts in your
cache store (not the `array` driver). Modules: `ANALYTICS_FIREWALL`,
`ANALYTICS_ERRORS`, `ANALYTICS_SERVER_EVENTS`, `ANALYTICS_INVENTORY`, `ANALYTICS_QUERIES`, `ANALYTICS_CALLS`, `ANALYTICS_QUEUES` (`false` turns one off).
`ANALYTICS_CAPTURE_LOGS=true` also sends exceptions you log at error or above
(`Log::error('...', ['exception' => $e])`). It works the same under Octane
(Swoole, RoadRunner, FrankenPHP): nothing of one request is kept for the next.
Queue jobs (`queue:work`) are
wrapped as jobs on their own; `ANALYTICS_SERVER_NAME=worker` names the service. To
protect only some routes, set `ANALYTICS_FIREWALL_GLOBAL=false` and add
`AnalyticsPlatform\Laravel\FirewallMiddleware` to them.

## Symfony

Symfony 6.4 or later. After `composer require analytics-platform/platform`,
add one line to `config/bundles.php`:

```php
AnalyticsPlatform\Symfony\AnalyticsPlatformBundle::class => ['all' => true],
```

and the keys to `.env.local`: `ANALYTICS_SITE_ID`, `ANALYTICS_SITE_SECRET`
and `ANALYTICS_ENDPOINT` (`ANALYTICS_FIREWALL_ENDPOINT`, its older name, works
too). Until the keys are set the site runs as before. The bundle registers the
platform, its rate limit counter and the subscriber; `HttpClientBreadcrumbs`
when `symfony/http-client` is installed; and `QueryMiddleware` on every
Doctrine connection when DBAL is. `LogProcessor` stays optional (below).

Options, all optional, in `config/packages/analytics_platform.yaml`. Any option
of the plain PHP package goes under `options`:

```yaml
analytics_platform:
    protect_only: ['/admin', 'checkout', 'account_*']
    options: { server_name: worker, firewall: { mode: monitor }, posture: { roots: ['%kernel.project_dir%/public'] } }
```

**Set up before the bundle?** The `services.yaml` block below still works on
its own, with no bundle. With both, a service you define yourself is kept and
the bundle's one of the same name is dropped, so nothing is registered twice.

```yaml
    AnalyticsPlatform\Platform:
        arguments:
            $options:
                site_id: '%env(default::ANALYTICS_SITE_ID)%'
                secret: '%env(default::ANALYTICS_SITE_SECRET)%'
                endpoint: '%env(default::ANALYTICS_FIREWALL_ENDPOINT)%'
                platform: symfony
                storage: '%kernel.project_dir%/var/analytics-platform'
                inventory: { root: '%kernel.project_dir%' }
                counter: '@AnalyticsPlatform\Symfony\CacheCounter'
    AnalyticsPlatform\Symfony\CacheCounter: ~
    AnalyticsPlatform\Symfony\PlatformSubscriber: ~
    # With symfony/http-client: its requests in the steps before an error, and their times.
    AnalyticsPlatform\Symfony\HttpClientBreadcrumbs: ~
    # With Doctrine DBAL 3.2 or later: every query's time (Server speed → Queries).
    AnalyticsPlatform\Symfony\QueryMiddleware:
        tags: [doctrine.middleware]
```

The subscriber runs before Symfony's own listeners on every request: the
tracker's addresses, the firewall and maintenance mode, then the security
headers on the response. An exception is sent when the visitor got a 5xx, so
a 404, an access denied, or an exception that `framework.exceptions` or
`#[WithHttpStatus]` turns into a 4xx is not. Server speed names each request by
its route's path (`/users/{id}`); the paths are read from your routes once and
kept next to the router's cache, so `cache:clear` reads them again. It works
the same under PHP-FPM and in a worker that serves many requests from one
process (FrankenPHP, RoadRunner, Swoole): nothing of one request is kept for the next.

Messenger workers (`messenger:consume`) are wrapped as jobs, named after the
message's class, and a command that fails is sent too. Failed form and JSON
logins count for bot protection, and logins and logouts go to the audit log.
In your code, ask for `AnalyticsPlatform\Platform` in a controller or service:
`$platform->track('purchase', [...])`.

- **Logged exceptions.** Register `AnalyticsPlatform\Symfony\LogProcessor: ~`
  in `services.yaml` (with the bundle too). It sends what you log with an exception
  at error or above (`$logger->error('...', ['exception' => $e])`), from any
  channel, like Laravel's `ANALYTICS_CAPTURE_LOGS`. Needs MonologBundle, which
  picks it up on its own: nothing goes in `monolog.yaml`. One logged and then
  thrown is sent once.
- **HttpClient.** `HttpClientBreadcrumbs` (registered by the bundle when
  `symfony/http-client` is installed) records each request your HttpClient
  makes (the default client and scoped ones): method, address without the query
  string, status, 0 when no answer came; and times each for Server speed →
  Calls by its host.
- **Only some routes.** `protect_only: ['/admin', 'checkout', 'account_*']`
  (under `analytics_platform:`, or under `$options` in `services.yaml`) puts the firewall and maintenance mode in front of those paths
  (and everything below them) and route names (`*` at the end: every name that
  starts so) and nowhere else. Timing, errors and the tracker's addresses stay
  on everywhere.
- **Database queries.** `QueryMiddleware` is a Doctrine DBAL middleware
  (DoctrineBundle 2.6 or later puts it on every connection by its tag): the
  ORM's queries and your own `Connection` calls, failures included. A query
  that fails while being prepared, before it runs, isn't counted.
- **Rate limit.** `CacheCounter` counts in APCu when the server has it, else in
  your app's cache (`cache.app`). A cache pool can't add one atomically, so
  under a burst of simultaneous requests it counts a little low; APCu is exact.

The visitor's address is `$request->getClientIp()`, so set
`framework.trusted_proxies` if you're behind a load balancer or Cloudflare.
Every option of the plain PHP package goes under `options:` (or `$options` in
`services.yaml`): `server_name: worker`, `proxy: false`,
`firewall: { mode: monitor }`, `posture: { roots: ['%kernel.project_dir%/public'] }`.

## Ad blockers

Many visitors use an ad blocker, and most blockers stop analytics. They
recognise **the address a script comes from** and **what it is called**, so a
tracker loaded from us is simply never counted.

Your site already runs on your own domain, so the package serves the tracker
and takes the visits itself. `protect()` (or Laravel's middleware, or Symfony's subscriber) answers
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
- A visitor's request waits on ours, so ours are short (1 second to connect, 2
  in all), and after three failures in a row we are left alone for 30 seconds:
  beacons get a `502` with `Retry-After` straight away (the tracker treats a lost
  beacon as lost and carries on) and a tracker file that failed isn't asked for
  again for 30 seconds. That state is shared between requests in APCu, else in
  a small file in the storage folder.
- A denied or banned address gets nothing from the proxy either (and is
  reported); beacons are never rate-limited, checked or matched against
  request rules.
- The visitor's address goes on as `X-Forwarded-For` (your collector needs it
  for the country, the daily visitor ID and the rate limit) and cookies never
  leave your server.
- Beacons are answered before the rest of the firewall, the crawler count and the timing,
  so your own analytics traffic doesn't appear as pages of your site.
- **WordPress does it for you**: the plugin adds a rewrite and answers through
  `px.php`, without loading WordPress at all. Settings → Site Analytics → Ad
  blockers says whether it's working.
- Switch it off with `'proxy' => false` (Laravel: `ANALYTICS_PROXY=false`; Symfony:
  `proxy: false`), or
  in the dashboard (Security → Server package).

## Other frameworks

`$platform->firewall()->check($ip, $method, $path, $userAgent, $accept, $passCookie)`
returns the decision without ending the request (`$accept` is the `Accept`
header and `$passCookie` the `__sg_pass` cookie, best as
`\AnalyticsPlatform\Challenge::cookieValues($cookieHeader)` from the raw
`Cookie` header, which a browser can send twice, for the browser check; leave
them out and no request is checked). When its `rule` is `challenge`, answer
with `$platform->firewall()->challengePage($ip, $method)`. Call
`$platform->afterResponse()` once the response has gone out.
