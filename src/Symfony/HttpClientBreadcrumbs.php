<?php
// What Symfony's HttpClient asked other services for: steps in the trail shown
// before an error, as Laravel records its Http client's requests (method,
// address without the query string, status; 0 when no answer came). On by
// registering this one service (README: "Symfony"): it decorates the client's
// transport, so the default client and every scoped one go through it, and
// each try of a retried request is a step of its own. Responses aren't
// changed or waited for; the status is read as it arrives.

namespace AnalyticsPlatform\Symfony;

use AnalyticsPlatform\Platform;
use Symfony\Component\HttpClient\AsyncDecoratorTrait;
use Symfony\Component\HttpClient\Response\AsyncContext;
use Symfony\Component\HttpClient\Response\AsyncResponse;
use Symfony\Contracts\HttpClient\ChunkInterface;
use Symfony\Contracts\HttpClient\Exception\TransportExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Symfony\Contracts\HttpClient\ResponseInterface;
use Symfony\Contracts\Service\ResetInterface;

#[\Symfony\Component\DependencyInjection\Attribute\AsDecorator('http_client.transport', onInvalid: \Symfony\Component\DependencyInjection\ContainerInterface::IGNORE_ON_INVALID_REFERENCE)]
class HttpClientBreadcrumbs implements HttpClientInterface, ResetInterface
{
    use AsyncDecoratorTrait;

    private $platform;

    public function __construct(HttpClientInterface $client, Platform $platform)
    {
        $this->client = $client;
        $this->platform = $platform;
    }

    public function request(string $method, string $url, array $options = array()): ResponseInterface
    {
        $platform = $this->platform;
        $recorded = false;
        return new AsyncResponse($this->client, $method, $url, $options, function (ChunkInterface $chunk, AsyncContext $context) use ($platform, $method, &$recorded) {
            // Read as RetryableHttpClient reads it: a timeout or a 1xx is
            // passed on, a failure is recorded and passed on, so the caller
            // gets it as it would without this.
            if (!$recorded) {
                try {
                    $first = !$chunk->isTimeout() && $chunk->getInformationalStatus() === null && $chunk->isFirst();
                } catch (TransportExceptionInterface $e) {
                    $recorded = true;
                    $platform->addRequestBreadcrumb($method, (string) $context->getInfo('url'), 0);
                    $first = false;
                }
                if ($first) {
                    $recorded = true;
                    $platform->addRequestBreadcrumb($method, (string) $context->getInfo('url'), $context->getStatusCode());
                }
            }
            yield $chunk;
        });
    }
}
