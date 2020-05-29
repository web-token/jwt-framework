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

namespace Jose\Component\NestedToken;

use Jose\Component\Encryption\JWELoaderFactory;
use Jose\Component\Signature\JWSLoaderFactory;

class NestedTokenLoaderFactory
{
    /**
     * @var JWELoaderFactory
     */
    private $jweLoaderFactory;

    /**
     * @var JWSLoaderFactory
     */
    private $jwsLoaderFactory;

    public function __construct(JWELoaderFactory $jweLoaderFactory, JWSLoaderFactory $jwsLoaderFactory)
    {
        $this->jweLoaderFactory = $jweLoaderFactory;
        $this->jwsLoaderFactory = $jwsLoaderFactory;
    }

    /**
     * This method creates a Nested Token Loader with the given encryption/signature algorithms, serializers, compression methods and header checkers.
     */
    public function create(array $jweSerializers, array $keyEncryptionAlgorithms, array $contentEncryptionAlgorithms, array $compressionMethods, array $jweHeaderCheckers, array $jwsSerializers, array $signatureAlgorithms, array $jwsHeaderCheckers): NestedTokenLoader
    {
        $jweLoader = $this->jweLoaderFactory->create($jweSerializers, $keyEncryptionAlgorithms, $contentEncryptionAlgorithms, $compressionMethods, $jweHeaderCheckers);
        $jwsLoader = $this->jwsLoaderFactory->create($jwsSerializers, $signatureAlgorithms, $jwsHeaderCheckers);

        return new NestedTokenLoader($jweLoader, $jwsLoader);
    }
}
