<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\KeyManagement\Tests;

use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use Http\Message\RequestFactory;
use Http\Message\ResponseFactory;

class MessageFactory implements ResponseFactory, RequestFactory
{
    public function createRequest($method, $uri, array $header = [], $body = null, $protocolVersion = '1.1')
    {
        return new Request($method, $uri, $header, $body, $protocolVersion);
    }

    public function createResponse($statusCode = 200, $reasonPhrase = null, array $header = [], $body = null, $protocolVersion = '1.1')
    {
        return new Response($statusCode, $header, $body, $protocolVersion, $reasonPhrase);
    }
}
