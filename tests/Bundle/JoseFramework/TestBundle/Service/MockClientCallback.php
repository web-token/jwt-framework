<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Tests\Bundle\JoseFramework\TestBundle\Service;

use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

final class MockClientCallback implements ClientInterface
{
    /**
     * @var ResponseInterface
     */
    private $response;

    public function set(ResponseInterface $response): void
    {
        $this->response = $response;
    }

    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        return $this->response;
    }
}