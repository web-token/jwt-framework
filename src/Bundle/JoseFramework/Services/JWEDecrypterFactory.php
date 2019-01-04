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
use Jose\Component\Encryption\Compression\CompressionMethodManagerFactory;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;

final class JWEDecrypterFactory
{
    private $algorithmManagerFactory;

    private $compressionMethodManagerFactory;

    private $eventDispatcher;

    public function __construct(AlgorithmManagerFactory $algorithmManagerFactory, CompressionMethodManagerFactory $compressionMethodManagerFactory, EventDispatcherInterface $eventDispatcher)
    {
        $this->algorithmManagerFactory = $algorithmManagerFactory;
        $this->compressionMethodManagerFactory = $compressionMethodManagerFactory;
        $this->eventDispatcher = $eventDispatcher;
    }

    public function create(array $keyEncryptionAlgorithms, array $contentEncryptionAlgorithms, array $compressionMethods): JWEDecrypter
    {
        $keyEncryptionAlgorithmManager = $this->algorithmManagerFactory->create($keyEncryptionAlgorithms);
        $contentEncryptionAlgorithmManager = $this->algorithmManagerFactory->create($contentEncryptionAlgorithms);
        $compressionMethodManager = $this->compressionMethodManagerFactory->create($compressionMethods);

        return new JWEDecrypter($keyEncryptionAlgorithmManager, $contentEncryptionAlgorithmManager, $compressionMethodManager, $this->eventDispatcher);
    }
}
