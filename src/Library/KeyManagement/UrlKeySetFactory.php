<?php

declare(strict_types=1);

namespace Jose\Component\KeyManagement;

use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use RuntimeException;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * @see \Jose\Tests\Component\KeyManagement\UrlKeySetFactoryTest
 */
abstract class UrlKeySetFactory
{
    public function __construct(
        private readonly ClientInterface|HttpClientInterface $client,
        private readonly null|RequestFactoryInterface $requestFactory = null
    ) {
        if ($this->client instanceof ClientInterface) {
            trigger_deprecation(
                'web-token/jwt-library',
                '3.3',
                'Using "%s" with an instance of "%s" is deprecated, use "%s" instead.',
                self::class,
                ClientInterface::class,
                HttpClientInterface::class
            );
        }
        if (! $this->client instanceof HttpClientInterface && $this->requestFactory === null) {
            throw new RuntimeException(qprintf(
                'The request factory must be provided when using an instance of "%s" as client.',
                ClientInterface::class
            ));
        }
    }

    protected function getContent(string $url, array $header = []): string
    {
        if ($this->client instanceof HttpClientInterface) {
            return $this->sendSymfonyRequest($url, $header);
        }
        return $this->sendPsrRequest($url, $header);
    }

    private function sendSymfonyRequest(string $url, array $header = []): string
    {
        $response = $this->client->request('GET', $url, [
            'headers' => $header,
        ]);

        if ($response->getStatusCode() >= 400) {
            throw new RuntimeException('Unable to get the key set.', $response->getStatusCode());
        }

        return $response->getContent();
    }

    private function sendPsrRequest(string $url, array $header = []): string
    {
        $request = $this->requestFactory->createRequest('GET', $url);
        foreach ($header as $k => $v) {
            $request = $request->withHeader($k, $v);
        }
        $response = $this->client->sendRequest($request);

        if ($response->getStatusCode() >= 400) {
            throw new RuntimeException('Unable to get the key set.', $response->getStatusCode());
        }

        return $response->getBody()
            ->getContents();
    }
}
