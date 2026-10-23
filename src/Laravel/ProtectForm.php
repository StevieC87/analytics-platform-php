<?php
// Form protection for Laravel routes: add it to a form's route
// (->middleware(\AnalyticsPlatform\Laravel\ProtectForm::class)). Spam goes
// back to the form with an error (or a 422 for JSON requests) and lands in
// Leads → Spam; otherwise $request->attributes->get('form_check') holds the result.

namespace AnalyticsPlatform\Laravel;

use AnalyticsPlatform\Platform;
use Closure;

class ProtectForm
{
    private $platform;

    public function __construct(Platform $platform)
    {
        $this->platform = $platform;
    }

    public function handle($request, Closure $next)
    {
        $result = $this->platform->checkForm($request->all(), $request->input('email'), $request->input('name'));
        $request->attributes->set('form_check', $result);
        if (!$result['spam']) {
            return $next($request);
        }
        $message = 'Your message looks automated, so it wasn\'t sent. Please try again.';
        if ($request->expectsJson()) {
            return response()->json(array('message' => $message), 422);
        }
        return back()->withInput()->withErrors(array('form' => $message));
    }
}
