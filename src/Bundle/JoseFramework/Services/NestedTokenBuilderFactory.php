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
use Jose\Component\Signature\Serializer\JWSSerializerManagerFactory;
use Psr\EventDispatcher\EventDispatcherInterface;

final class NestedTokenBuilderFactory
{
    /**
     * @var JWEBuilderFactory
     */
    private $jweBuilderFactory;

    /**
     * @var JWESerializerManagerFactory
     */
    private $jweSerializerManagerFactory;

    /**
     * @var JWSBuilderFactory
     */
    private $jwsBuilderFactory;

    /**
     * @var JWSSerializerManagerFactory
     */
    private $jwsSerializerManagerFactory;

    /**
     * @var EventDispatcherInterface
     */
    private $eventDispatcher;

    public function __construct(JWEBuilderFactory $jweBuilderFactory, JWESerializerManagerFactory $jweSerializerManagerFactory, JWSBuilderFactory $jwsBuilderFactory, JWSSerializerManagerFactory $jwsSerializerManagerFactory, EventDispatcherInterface $eventDispatcher)
    {
        $this->jweBuilderFactory = $jweBuilderFactory;
        $this->jweSerializerManagerFactory = $jweSerializerManagerFactory;
        $this->jwsBuilderFactory = $jwsBuilderFactory;
        $this->jwsSerializerManagerFactory = $jwsSerializerManagerFactory;
        $this->eventDispatcher = $eventDispatcher;
    }

    public function create(array $jwe_serializers, array $keyEncryptionAlgorithms, array $contentEncryptionAlgorithms, array $compressionMethods, array $jws_serializers, array $signatureAlgorithms): NestedTokenBuilder
    {
        $jweBuilder = $this->jweBuilderFactory->create($keyEncryptionAlgorithms, $contentEncryptionAlgorithms, $compressionMethods);
        $jweSerializerManager = $this->jweSerializerManagerFactory->create($jwe_serializers);
        $jwsBuilder = $this->jwsBuilderFactory->create($signatureAlgorithms);
        $jwsSerializerManager = $this->jwsSerializerManagerFactory->create($jws_serializers);

        return new NestedTokenBuilder($jweBuilder, $jweSerializerManager, $jwsBuilder, $jwsSerializerManager, $this->eventDispatcher);
    }
}
