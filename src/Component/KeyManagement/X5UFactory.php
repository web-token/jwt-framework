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
use Jose\Component\Core\Converter\JsonConverter;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\KeyConverter\KeyConverter;

/**
 * Class X5UFactory.
 */
final class X5UFactory extends UrlKeySetFactory
{
    private $jsonConverter;

    /**
     * X5UFactory constructor.
     *
     * @param JsonConverter  $jsonConverter
     * @param HttpClient     $client
     * @param MessageFactory $messageFactory
     */
    public function __construct(JsonConverter $jsonConverter, HttpClient $client, MessageFactory $messageFactory)
    {
        $this->jsonConverter = $jsonConverter;
        parent::__construct($client, $messageFactory);
    }

    /**
     * @param string $url
     * @param array  $headers
     *
     * @throws \InvalidArgumentException
     *
     * @return JWKSet
     */
    public function loadFromUrl(string $url, array $headers = []): JWKSet
    {
        $content = $this->getContent($url, $headers);
        $data = $this->jsonConverter->decode($content);
        if (!is_array($data)) {
            throw new \InvalidArgumentException('Invalid content.');
        }

        $keys = [];
        foreach ($data as $kid => $cert) {
            $jwk = KeyConverter::loadKeyFromCertificate($cert);
            if (is_string($kid)) {
                $jwk['kid'] = $kid;
                $keys[$kid] = JWK::create($jwk);
            } else {
                $keys[] = JWK::create($jwk);
            }
        }

        return JWKSet::createFromKeys($keys);
    }
}
