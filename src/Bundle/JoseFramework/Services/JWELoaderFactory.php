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

namespace Jose\Bundle\JoseFramework\Services;

use Jose\Component\Encryption\Serializer\JWESerializerManagerFactory;
use Psr\EventDispatcher\EventDispatcherInterface;

final class JWELoaderFactory
{
    /**
     * @var EventDispatcherInterface
     */
    private $eventDispatcher;

    /**
     * @var JWESerializerManagerFactory
     */
    private $jweSerializerManagerFactory;

    /**
     * @var JWEDecrypterFactory
     */
    private $jweDecrypterFactory;

    /**
     * @var null|HeaderCheckerManagerFactory
     */
    private $headerCheckerManagerFactory;

    public function __construct(JWESerializerManagerFactory $jweSerializerManagerFactory, JWEDecrypterFactory $jweDecrypterFactory, ?HeaderCheckerManagerFactory $headerCheckerManagerFactory, EventDispatcherInterface $eventDispatcher)
    {
        $this->eventDispatcher = $eventDispatcher;
        $this->jweSerializerManagerFactory = $jweSerializerManagerFactory;
        $this->jweDecrypterFactory = $jweDecrypterFactory;
        $this->headerCheckerManagerFactory = $headerCheckerManagerFactory;
    }

    public function create(array $serializers, array $keyEncryptionAlgorithms, array $contentEncryptionAlgorithms, array $compressionMethods, array $headerCheckers = []): JWELoader
    {
        $serializerManager = $this->jweSerializerManagerFactory->create($serializers);
        $jweDecrypter = $this->jweDecrypterFactory->create($keyEncryptionAlgorithms, $contentEncryptionAlgorithms, $compressionMethods);
        if (null !== $this->headerCheckerManagerFactory) {
            $headerCheckerManager = $this->headerCheckerManagerFactory->create($headerCheckers);
        } else {
            $headerCheckerManager = null;
        }

        return new JWELoader($serializerManager, $jweDecrypter, $headerCheckerManager, $this->eventDispatcher);
    }
}
