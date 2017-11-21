<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\KeyManagement;

use Http\Client\HttpClient;
use Http\Message\RequestFactory;

/**
 * Class UrlKeySetFactory.
 */
abstract class UrlKeySetFactory
{
    /**
     * @var HttpClient
     */
    private $client;

    /**
     * @var RequestFactory
     */
    private $requestFactory;

    /**
     * UrlKeySetFactory constructor.
     *
     * @param HttpClient     $client
     * @param RequestFactory $requestFactory
     */
    public function __construct(HttpClient $client, RequestFactory $requestFactory)
    {
        $this->client = $client;
        $this->requestFactory = $requestFactory;
    }

    /**
     * @param string $url
     * @param array  $headers
     *
     * @throws \RuntimeException
     *
     * @return string
     */
    protected function getContent(string $url, array $headers = []): string
    {
        $request = $this->requestFactory->createRequest('GET', $url, $headers);
        $response = $this->client->sendRequest($request);

        if ($response->getStatusCode() >= 400) {
            throw new \RuntimeException('Unable to get the key set.', $response->getStatusCode());
        }

        return $response->getBody()->getContents();
    }
}
