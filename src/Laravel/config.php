<?php
// The analytics package: firewall, error monitoring, server analytics (php artisan vendor:publish --tag=analytics-firewall
// copies this to config/). Rules, mode and reports are in your analytics
// dashboard under Security → Firewall.

return [
    'site_id' => env('ANALYTICS_SITE_ID'),
    // Site settings in your dashboard. Keep it in .env, never in the browser.
    'secret' => env('ANALYTICS_SITE_SECRET'),
    'endpoint' => env('ANALYTICS_FIREWALL_ENDPOINT'),
    // 'monitor' or 'block' overrides the dashboard; empty follows it.
    'mode' => env('ANALYTICS_FIREWALL_MODE'),
    // Modules: each can also be switched off in the dashboard (Security → Settings → Server package).
    // Serves the tracker and takes visits under your own domain, so ad
    // blockers can't hide those visitors (README: "Ad blockers").
    'proxy' => env('ANALYTICS_PROXY', true),
    'firewall' => env('ANALYTICS_FIREWALL', true),
    'errors' => env('ANALYTICS_ERRORS', true),
    'analytics' => env('ANALYTICS_SERVER_EVENTS', true),
    'performance' => env('ANALYTICS_PERFORMANCE', true),
    // The Composer packages and PHP version, once a day, for the Security check.
    'inventory' => env('ANALYTICS_INVENTORY', true),
    // How the server is set up, once a day, for the Security check: php.ini
    // settings, and a walk of public/ for files that shouldn't be there
    // (sdk/protocols/posture.md). Reads only; off unless you turn it on.
    'posture' => env('ANALYTICS_POSTURE', false),
    // Check every request. Off: add AnalyticsPlatform\Laravel\FirewallMiddleware to the routes you want.
    'global' => env('ANALYTICS_FIREWALL_GLOBAL', true),
];
