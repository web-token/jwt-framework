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

namespace Jose\Component\Encryption;

use Jose\Component\Encryption\Serializer\JWESerializerManagerFactory;
use Jose\Component\Signature\JWSBuilderFactory;
use Jose\Component\Signature\Serializer\JWSSerializerManagerFactory;

class NestedTokenBuilderFactory
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
     * NestedTokenBuilderFactory constructor.
     *
     * @param JWEBuilderFactory           $jweBuilderFactory
     * @param JWESerializerManagerFactory $jweSerializerManagerFactory
     * @param JWSBuilderFactory           $jwsBuilderFactory
     * @param JWSSerializerManagerFactory $jwsSerializerManagerFactory
     */
    public function __construct(JWEBuilderFactory $jweBuilderFactory, JWESerializerManagerFactory $jweSerializerManagerFactory, JWSBuilderFactory $jwsBuilderFactory, JWSSerializerManagerFactory $jwsSerializerManagerFactory)
    {
        $this->jweBuilderFactory = $jweBuilderFactory;
        $this->jweSerializerManagerFactory = $jweSerializerManagerFactory;
        $this->jwsBuilderFactory = $jwsBuilderFactory;
        $this->jwsSerializerManagerFactory = $jwsSerializerManagerFactory;
    }

    /**
     * @param array $jwe_serializers
     * @param array $keyEncryptionAlgorithms
     * @param array $contentEncryptionAlgorithms
     * @param array $compressionMethods
     * @param array $jws_serializers
     * @param array $signatureAlgorithms
     *
     * @return NestedTokenBuilder
     */
    public function create(array $jwe_serializers, array $keyEncryptionAlgorithms, array $contentEncryptionAlgorithms, array $compressionMethods, array $jws_serializers, array $signatureAlgorithms): NestedTokenBuilder
    {
        $jweBuilder = $this->jweBuilderFactory->create($keyEncryptionAlgorithms, $contentEncryptionAlgorithms, $compressionMethods);
        $jweSerializerManager = $this->jweSerializerManagerFactory->create($jwe_serializers);
        $jwsBuilder = $this->jwsBuilderFactory->create($signatureAlgorithms);
        $jwsSerializerManager = $this->jwsSerializerManagerFactory->create($jws_serializers);

        return new NestedTokenBuilder($jweBuilder, $jweSerializerManager, $jwsBuilder, $jwsSerializerManager);
    }
}
