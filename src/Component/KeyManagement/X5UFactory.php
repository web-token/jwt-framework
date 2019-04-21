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

namespace Jose\Component\KeyManagement;

use Http\Client\HttpClient;
use Http\Message\RequestFactory;
use Jose\Component\Core\Converter\JsonConverter;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\KeyConverter\KeyConverter;

class X5UFactory extends UrlKeySetFactory
{
    private $jsonConverter;

    /**
     * X5UFactory constructor.
     */
    public function __construct(?JsonConverter $jsonConverter, HttpClient $client, RequestFactory $requestFactory)
    {
        $this->jsonConverter = $jsonConverter ?? new \Jose\Component\Core\Util\JsonConverter();
        parent::__construct($client, $requestFactory);
    }

    /**
     * This method will try to fetch the url a retrieve the key set.
     * Throws an exception in case of failure.
     *
     * @throws \InvalidArgumentException
     */
    public function loadFromUrl(string $url, array $header = []): JWKSet
    {
        $content = $this->getContent($url, $header);
        $data = $this->jsonConverter->decode($content);
        if (!\is_array($data)) {
            throw new \RuntimeException('Invalid content.');
        }

        $keys = [];
        foreach ($data as $kid => $cert) {
            if (false === \mb_strpos($cert, '-----BEGIN CERTIFICATE-----')) {
                $cert = '-----BEGIN CERTIFICATE-----'.PHP_EOL.$cert.PHP_EOL.'-----END CERTIFICATE-----';
            }
            $jwk = KeyConverter::loadKeyFromCertificate($cert);
            if (\is_string($kid)) {
                $jwk['kid'] = $kid;
                $keys[$kid] = new JWK($jwk);
            } else {
                $keys[] = new JWK($jwk);
            }
        }

        return new JWKSet($keys);
    }
}
