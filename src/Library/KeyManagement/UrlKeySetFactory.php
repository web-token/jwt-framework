<?php

declare(strict_types=1);

namespace Jose\Component\KeyManagement;

use RuntimeException;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * @see \Jose\Tests\Component\KeyManagement\UrlKeySetFactoryTest
 */
abstract class UrlKeySetFactory
{
    public function __construct(
        private readonly HttpClientInterface $client,
    ) {
    }

    /**
     * @param array<string, string|string[]> $header
     */
    protected function getContent(string $url, array $header = []): string
    {
        $response = $this->client->request('GET', $url, [
            'headers' => $header,
        ]);

        if ($response->getStatusCode() >= 400) {
            throw new RuntimeException('Unable to get the key set.', $response->getStatusCode());
        }

        return $response->getContent();
    }
}
