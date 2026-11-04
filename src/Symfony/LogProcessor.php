<?php
// Also sends the exceptions your code logs ($logger->error('...', ['exception'
// => $e])), as Laravel's 'capture_logs' does: on by registering this one
// service (README: "Symfony"). MonologBundle autoconfigures it as a processor
// on every channel, so no monolog.yaml handler is needed and no handler before
// it can stop it seeing a record. It changes nothing in the record.
//
// Records at error or above with a Throwable as their 'exception'. Not
// Symfony's own reports of what the subscriber already sends (an uncaught
// exception, a failed command or message: the request, console, messenger
// and php channels), which would send a 404 Symfony logs at error level, or a
// mistyped command. An exception logged and then thrown on is sent once, as
// the error it became (Errors' 'logged' upgrade).

namespace AnalyticsPlatform\Symfony;

use AnalyticsPlatform\Platform;

#[\Monolog\Attribute\AsMonologProcessor]
class LogProcessor
{
    const LEVEL = 400; // Monolog's ERROR
    const OWN_CHANNELS = array('request', 'console', 'messenger', 'php');

    private $platform;
    private $requests;

    public function __construct(Platform $platform, ?\Symfony\Component\HttpFoundation\RequestStack $requests = null)
    {
        $this->platform = $platform;
        $this->requests = $requests;
    }

    // A Monolog 3 LogRecord or a Monolog 2 array: both are read as an array.
    public function __invoke($record)
    {
        try {
            $context = $record['context'];
            $error = isset($context['exception']) ? $context['exception'] : null;
            if ($error instanceof \Throwable && (int) $record['level'] >= self::LEVEL
                && !in_array((string) $record['channel'], self::OWN_CHANNELS, true)) {
                $request = $this->requests ? $this->requests->getMainRequest() : null;
                // A job's (Messenger, the console) name comes from Platform; a request's from here.
                $fields = $request ? PlatformSubscriber::requestFields($request, (string) $request->attributes->get(PlatformSubscriber::ROUTE)) : null;
                // Sent after the response, the job or the command (PlatformSubscriber).
                $this->platform->captureException($error, $fields, 0, 'logged');
            }
        } catch (\Throwable $e) {
            // never break logging
        }
        return $record;
    }
}
