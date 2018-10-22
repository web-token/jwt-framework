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

namespace Jose\Bundle\JoseFramework\Services;

use Jose\Component\Core\AlgorithmManagerFactory;
use Jose\Component\Core\Converter\JsonConverter;
use Jose\Component\Encryption\Compression\CompressionMethodManagerFactory;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;

final class JWEBuilderFactory
{
    private $eventDispatcher;
    private $jsonEncoder;
    private $algorithmManagerFactory;
    private $compressionMethodManagerFactory;

    public function __construct(JsonConverter $jsonEncoder, AlgorithmManagerFactory $algorithmManagerFactory, CompressionMethodManagerFactory $compressionMethodManagerFactory, EventDispatcherInterface $eventDispatcher)
    {
        $this->jsonEncoder = $jsonEncoder;
        $this->eventDispatcher = $eventDispatcher;
        $this->algorithmManagerFactory = $algorithmManagerFactory;
        $this->compressionMethodManagerFactory = $compressionMethodManagerFactory;
    }

    /**
     * This method creates a JWEBuilder using the given algorithm aliases.
     *
     * @param string[] $keyEncryptionAlgorithms
     * @param string[] $contentEncryptionAlgorithm
     * @param string[] $compressionMethods
     */
    public function create(array $keyEncryptionAlgorithms, array $contentEncryptionAlgorithm, array $compressionMethods): JWEBuilder
    {
        $keyEncryptionAlgorithmManager = $this->algorithmManagerFactory->create($keyEncryptionAlgorithms);
        $contentEncryptionAlgorithmManager = $this->algorithmManagerFactory->create($contentEncryptionAlgorithm);
        $compressionMethodManager = $this->compressionMethodManagerFactory->create($compressionMethods);

        return new JWEBuilder($this->jsonEncoder, $keyEncryptionAlgorithmManager, $contentEncryptionAlgorithmManager, $compressionMethodManager, $this->eventDispatcher);
    }
}
