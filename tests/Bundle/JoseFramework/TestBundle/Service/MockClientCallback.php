<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\TestBundle\Service;

use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;

final class MockClientCallback extends MockHttpClient
{
    private null|MockResponse $response = null;

    public function __invoke(string $method, string $url, array $options = []): ?MockResponse
    {
        if ($this->response === null) {
            throw new RuntimeException(sprintf(
                'Unable to find a response for a %s request to the URL %s',
                $method,
                $url
            ));
        }

        return $this->response;
    }

    public function set(MockResponse $response): void
    {
        $this->response = $response;
    }
}
