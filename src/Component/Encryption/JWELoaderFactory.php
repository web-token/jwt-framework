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

namespace Jose\Component\Encryption;

use Jose\Component\Checker\HeaderCheckerManagerFactory;
use Jose\Component\Encryption\Serializer\JWESerializerManagerFactory;

class JWELoaderFactory
{
    /**
     * @var JWEDecrypterFactory
     */
    private $jweDecrypterFactory;

    /**
     * @var JWESerializerManagerFactory
     */
    private $jweSerializerManagerFactory;

    /**
     * @var null|HeaderCheckerManagerFactory
     */
    private $headerCheckerManagerFactory;

    /**
     * JWELoaderFactory constructor.
     */
    public function __construct(JWESerializerManagerFactory $jweSerializerManagerFactory, JWEDecrypterFactory $jweDecrypterFactory, ?HeaderCheckerManagerFactory $headerCheckerManagerFactory)
    {
        $this->jweSerializerManagerFactory = $jweSerializerManagerFactory;
        $this->jweDecrypterFactory = $jweDecrypterFactory;
        $this->headerCheckerManagerFactory = $headerCheckerManagerFactory;
    }

    /**
     * Creates a JWELoader using the given serializer aliases, encryption algorithm aliases, compression method aliases
     * and header checker aliases.
     */
    public function create(array $serializers, array $keyEncryptionAlgorithms, array $contentEncryptionAlgorithms, array $compressionMethods, array $headerCheckers = []): JWELoader
    {
        $serializerManager = $this->jweSerializerManagerFactory->create($serializers);
        $jweDecrypter = $this->jweDecrypterFactory->create($keyEncryptionAlgorithms, $contentEncryptionAlgorithms, $compressionMethods);
        if (null !== $this->headerCheckerManagerFactory) {
            $headerCheckerManager = $this->headerCheckerManagerFactory->create($headerCheckers);
        } else {
            $headerCheckerManager = null;
        }

        return new JWELoader($serializerManager, $jweDecrypter, $headerCheckerManager);
    }
}
