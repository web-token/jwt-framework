<?php

declare(strict_types=1);

namespace Jose\Component\Encryption;

use Jose\Component\Core\AlgorithmManagerFactory;
use Jose\Component\Encryption\Compression\CompressionMethodManagerFactory;

class JWEBuilderFactory
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
     * Creates a JWE Builder object using the given key encryption algorithms, content encryption algorithms and
     * compression methods.
     *
     * @param array<string> $encryptionAlgorithms
     * @param null|array<string> $contentEncryptionAlgorithm
     * @param null|string[] $compressionMethods
     */
    public function create(
        array $encryptionAlgorithms,
        null|array $contentEncryptionAlgorithm = null,
        null|array $compressionMethods = null
    ): JWEBuilder {
        if ($contentEncryptionAlgorithm !== null) {
            trigger_deprecation(
                'web-token/jwt-library',
                '3.3.0',
                'The parameter "$contentEncryptionAlgorithm" is deprecated and will be removed in 4.0.0. Please set "null" instead.'
            );
            $encryptionAlgorithms = array_merge($encryptionAlgorithms, $contentEncryptionAlgorithm);
        }
        $encryptionAlgorithmManager = $this->algorithmManagerFactory->create($encryptionAlgorithms);
        $compressionMethodManager = $compressionMethods === null ? null : $this->compressionMethodManagerFactory?->create(
            $compressionMethods
        );

        return new JWEBuilder($encryptionAlgorithmManager, null, $compressionMethodManager);
    }
}
