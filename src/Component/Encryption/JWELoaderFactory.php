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

namespace Jose\Component\Encryption;

use Jose\Component\Checker\HeaderCheckerManagerFactory;
use Jose\Component\Core\AlgorithmManagerFactory;
use Jose\Component\Encryption\Compression\CompressionMethodManagerFactory;
use Jose\Component\Encryption\Serializer\JWESerializerManagerFactory;

/**
 * Class JWELoaderFactory.
 */
final class JWELoaderFactory
{
    /**
     * @var AlgorithmManagerFactory
     */
    private $algorithmManagerFactory;

    /**
     * @var CompressionMethodManagerFactory
     */
    private $compressionMethodManagerFactory;

    /**
     * @var HeaderCheckerManagerFactory
     */
    private $headerCheckerManagerFactory;

    /**
     * @var JWESerializerManagerFactory
     */
    private $serializerManagerFactory;

    /**
     * JWELoaderFactory constructor.
     *
     * @param AlgorithmManagerFactory         $algorithmManagerFactory
     * @param CompressionMethodManagerFactory $compressionMethodManagerFactory
     * @param HeaderCheckerManagerFactory     $headerCheckerManagerFactory
     */
    public function __construct(AlgorithmManagerFactory $algorithmManagerFactory, CompressionMethodManagerFactory $compressionMethodManagerFactory, HeaderCheckerManagerFactory $headerCheckerManagerFactory, JWESerializerManagerFactory $serializerManagerFactory)
    {
        $this->algorithmManagerFactory = $algorithmManagerFactory;
        $this->compressionMethodManagerFactory = $compressionMethodManagerFactory;
        $this->headerCheckerManagerFactory = $headerCheckerManagerFactory;
        $this->serializerManagerFactory = $serializerManagerFactory;
    }

    /**
     * @param string[] $keyEncryptionAlgorithms
     * @param string[] $contentEncryptionAlgorithms
     * @param string[] $compressionMethods
     * @param string[] $headerCheckers
     * @param string[] $serializers
     *
     * @return JWELoader
     */
    public function create(array $keyEncryptionAlgorithms, array $contentEncryptionAlgorithms, array $compressionMethods, array $headerCheckers, array $serializers): JWELoader
    {
        $keyEncryptionAlgorithmManager = $this->algorithmManagerFactory->create($keyEncryptionAlgorithms);
        $contentEncryptionAlgorithmManager = $this->algorithmManagerFactory->create($contentEncryptionAlgorithms);
        $compressionMethodManager = $this->compressionMethodManagerFactory->create($compressionMethods);
        $headerCheckerManager = $this->headerCheckerManagerFactory->create($headerCheckers);
        $serializerManagers = $this->serializerManagerFactory->create($serializers);

        return new JWELoader($keyEncryptionAlgorithmManager, $contentEncryptionAlgorithmManager, $compressionMethodManager, $headerCheckerManager, $serializerManagers);
    }
}
