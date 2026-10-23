<?php
// Error monitoring module: the site's PHP errors go to the collector (POST
// /events/server-errors), where they join the browser's errors in the Errors
// report. install() catches uncaught exceptions (the handler that was there
// still runs); onShutdown() reads a fatal error (Platform calls it at
// shutdown); captureException() sends errors you catch. Errors wait in
// memory and are sent after the response (Platform::afterResponse).

namespace AnalyticsPlatform;

class Errors
{
    const BATCH = 10;
    const QUEUE_MAX = 50;
    const FATAL = 85; // E_ERROR | E_PARSE | E_CORE_ERROR | E_COMPILE_ERROR

    private $core;
    private $options;
    private $queue = array();
    private $previous = null;
    private $installed = false;
    private $fatalRead = false;

    // Options: server_name (default the host name), root (paths are made
    // relative to it; default the document root's parent), release (which build
    // this is, for "introduced in" in the Errors report; default the
    // ANALYTICS_RELEASE environment variable), before_send
    // (callable($event, $error): change an event, or return null to drop it).
    public function __construct(Core $core, array $options = array())
    {
        $this->core = $core;
        $root = isset($_SERVER['DOCUMENT_ROOT']) && $_SERVER['DOCUMENT_ROOT'] !== '' ? dirname($_SERVER['DOCUMENT_ROOT']) : getcwd();
        $this->options = $options + array(
            'server_name' => function_exists('gethostname') ? gethostname() : '',
            'root' => $root,
            'release' => getenv('ANALYTICS_RELEASE') ?: '',
            'before_send' => null,
        );
    }

    public function install()
    {
        if ($this->installed) {
            return;
        }
        $this->installed = true;
        $this->previous = set_exception_handler(array($this, 'onException'));
    }

    public function onException($error)
    {
        $this->captureException($error, $this->requestFields(), 500, 'error');
        if (is_callable($this->previous)) {
            call_user_func($this->previous, $error);
            return;
        }
        // As PHP would without a handler.
        if (!headers_sent()) {
            http_response_code(500);
        }
        error_log('PHP Fatal error:  Uncaught ' . $error);
    }

    // Fatal errors can't be caught; they're read here, after the fact.
    public function onShutdown()
    {
        $last = error_get_last();
        if ($this->fatalRead || !$last || !($last['type'] & self::FATAL) || !$this->core->isOn('errors')) {
            return;
        }
        $this->fatalRead = true;
        $this->add(array(
            'message' => (string) $last['message'],
            'error_type' => 'FatalError',
            'stack' => '  File "' . $this->relative($last['file']) . '", line ' . (int) $last['line'] . ', in (fatal error)',
            'kind' => 'error',
            'status_code' => 500,
        ) + $this->requestFields(), null);
    }

    private function relative($text)
    {
        $root = rtrim((string) $this->options['root'], '/\\');
        return $root === '' ? (string) $text : str_replace($root . '/', '', (string) $text);
    }

    // Frames as "File ..., line ..., in ..." (innermost last), which the
    // collector reads like a Python traceback to group issues.
    // A PHP trace frame holds a call site and the function called; the call
    // site is inside the next frame's function.
    private function stack($error)
    {
        $trace = $error->getTrace();
        $name = function ($frame) {
            if (!$frame || !isset($frame['function'])) {
                return '{main}';
            }
            return (isset($frame['class']) ? $frame['class'] . $frame['type'] : '') . $frame['function'];
        };
        $frames = array(array($error->getFile(), $error->getLine(), $name(isset($trace[0]) ? $trace[0] : null)));
        foreach ($trace as $i => $frame) {
            if (isset($frame['file'])) {
                $frames[] = array($frame['file'], $frame['line'], $name(isset($trace[$i + 1]) ? $trace[$i + 1] : null));
            }
        }
        $lines = array();
        foreach (array_reverse($frames) as $frame) {
            $lines[] = '  File "' . $this->relative($frame[0]) . '", line ' . (int) $frame[1] . ', in ' . $frame[2];
        }
        return "Traceback (most recent call last):\n" . implode("\n", $lines) . "\n" . get_class($error) . ': ' . $error->getMessage();
    }

    public function requestFields()
    {
        $path = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '';
        return array(
            'method' => isset($_SERVER['REQUEST_METHOD']) ? (string) $_SERVER['REQUEST_METHOD'] : '',
            'path' => explode('?', (string) $path, 2)[0],
            'session_id' => Platform::sessionIdFromRequest(),
        );
    }

    // $request: method, path, route, session_id (default: the current request).
    public function captureException($error, $request = null, $status = 0, $kind = 'handled')
    {
        if (!$this->core->isOn('errors')) {
            return;
        }
        try {
            $isError = $error instanceof \Throwable;
            $event = array(
                'message' => $isError ? ($error->getMessage() !== '' ? $error->getMessage() : get_class($error)) : (string) $error,
                'error_type' => $isError ? (new \ReflectionClass($error))->getShortName() : 'Error',
                'stack' => $isError ? $this->stack($error) : '',
                'kind' => $kind,
                'status_code' => (int) $status,
            );
            foreach (($request === null ? $this->requestFields() : $request) as $key => $value) {
                if (in_array($key, array('method', 'path', 'route', 'session_id'), true)) {
                    $event[$key] = (string) $value;
                }
            }
            $this->add($event, $error);
        } catch (\Throwable $failure) {
            // never break the site
        }
    }

    private function add(array $event, $error)
    {
        $event += array(
            'runtime' => 'PHP',
            'runtime_version' => PHP_VERSION,
            'os' => PHP_OS_FAMILY,
            'server_name' => substr((string) $this->options['server_name'], 0, 100),
            'release' => substr(preg_replace('/[^\w.+-]/', '', (string) $this->options['release']), 0, 64),
        );
        if (is_callable($this->options['before_send'])) {
            $event = call_user_func($this->options['before_send'], $event, $error);
            if (!$event) {
                return;
            }
        }
        if (count($this->queue) < self::QUEUE_MAX) {
            $this->queue[] = $event;
        }
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
            $this->core->http('POST', '/events/server-errors', array('errors' => $batch), array(), 'body');
        }
    }
}
