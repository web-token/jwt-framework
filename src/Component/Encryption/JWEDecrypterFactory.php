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

use Jose\Component\Core\AlgorithmManagerFactory;
use Jose\Component\Encryption\Compression\CompressionMethodManagerFactory;

/**
 * Class JWEDecrypterFactory.
 */
final class JWEDecrypterFactory
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
     * JWEDecrypterFactory constructor.
     *
     * @param AlgorithmManagerFactory         $algorithmManagerFactory
     * @param CompressionMethodManagerFactory $compressionMethodManagerFactory
     */
    public function __construct(AlgorithmManagerFactory $algorithmManagerFactory, CompressionMethodManagerFactory $compressionMethodManagerFactory)
    {
        $this->algorithmManagerFactory = $algorithmManagerFactory;
        $this->compressionMethodManagerFactory = $compressionMethodManagerFactory;
    }

    /**
     * @param string[] $keyEncryptionAlgorithms
     * @param string[] $contentEncryptionAlgorithms
     * @param string[] $compressionMethods
     *
     * @return JWEDecrypter
     */
    public function create(array $keyEncryptionAlgorithms, array $contentEncryptionAlgorithms, array $compressionMethods): JWEDecrypter
    {
        $keyEncryptionAlgorithmManager = $this->algorithmManagerFactory->create($keyEncryptionAlgorithms);
        $contentEncryptionAlgorithmManager = $this->algorithmManagerFactory->create($contentEncryptionAlgorithms);
        $compressionMethodManager = $this->compressionMethodManagerFactory->create($compressionMethods);

        return new JWEDecrypter($keyEncryptionAlgorithmManager, $contentEncryptionAlgorithmManager, $compressionMethodManager);
    }
}
