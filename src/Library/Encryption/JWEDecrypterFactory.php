<?php

declare(strict_types=1);

namespace Jose\Component\Encryption;

use Jose\Component\Core\AlgorithmManagerFactory;
use Jose\Component\Encryption\Compression\CompressionMethodManagerFactory;

class JWEDecrypterFactory
{
    public function __construct(
        private readonly AlgorithmManagerFactory $algorithmManagerFactory,
        private readonly null|CompressionMethodManagerFactory $compressionMethodManagerFactory = null
    ) {
        if ($compressionMethodManagerFactory !== null) {
            trigger_deprecation(
                'web-token/jwt-library',
                '3.3.0',
                'The parameter "$compressionMethodManagerFactory" is deprecated and will be removed in 4.0.0. Compression is not recommended for JWE. Please set "null" instead.'
            );
        }
    }

    /**
     * Creates a JWE Decrypter object using the given key encryption algorithms, content encryption algorithms and
     * compression methods.
     *
     * @param string[] $encryptionAlgorithms
     * @param null|string[] $contentEncryptionAlgorithms
     * @param null|string[] $compressionMethods
     */
    public function create(
        array $encryptionAlgorithms,
        null|array $contentEncryptionAlgorithms = null,
        null|array $compressionMethods = null
    ): JWEDecrypter {
        if ($contentEncryptionAlgorithms !== null) {
            $encryptionAlgorithms = array_merge($encryptionAlgorithms, $contentEncryptionAlgorithms);
        }

        $algorithmManager = $this->algorithmManagerFactory->create($encryptionAlgorithms);
        $compressionMethodManager = $compressionMethods === null ? null : $this->compressionMethodManagerFactory?->create(
            $compressionMethods
        );

        return new JWEDecrypter($algorithmManager, null, $compressionMethodManager);
    }
}
