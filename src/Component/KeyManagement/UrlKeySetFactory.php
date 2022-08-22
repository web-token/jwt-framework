<?php

declare(strict_types=1);

namespace Jose\Component\KeyManagement;

use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use RuntimeException;

/**
 * @see \Jose\Tests\Component\KeyManagement\UrlKeySetFactoryTest
 */
abstract class UrlKeySetFactory
{
    public function __construct(
        private readonly ClientInterface $client,
        private readonly RequestFactoryInterface $requestFactory
    ) {
    }

    protected function getContent(string $url, array $header = []): string
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
