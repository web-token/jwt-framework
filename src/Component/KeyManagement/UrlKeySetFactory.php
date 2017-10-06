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
use Http\Message\MessageFactory;

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
     * @var MessageFactory
     */
    private $messageFactory;

    /**
     * UrlKeySetFactory constructor.
     *
     * @param HttpClient     $client
     * @param MessageFactory $messageFactory
     */
    public function __construct(HttpClient $client, MessageFactory $messageFactory)
    {
        $this->client = $client;
        $this->messageFactory = $messageFactory;
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
        $request = $this->messageFactory->createRequest('GET', $url, $headers);
        $response = $this->client->sendRequest($request);

        if (200 !== $response->getStatusCode()) {
            throw new \RuntimeException('Unable to get the key set.', $response->getStatusCode());
        }

        return $response->getBody()->getContents();
    }
}
