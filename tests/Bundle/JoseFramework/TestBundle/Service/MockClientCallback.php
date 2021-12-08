<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\TestBundle\Service;

use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

final class MockClientCallback implements ClientInterface
{
    private ?ResponseInterface $response = null;

    public function set(ResponseInterface $response): void
    {
        $this->response = $response;
    }

    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        return $this->response;
    }
}
