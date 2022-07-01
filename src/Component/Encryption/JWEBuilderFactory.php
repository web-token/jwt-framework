<?php

declare(strict_types=1);

namespace Jose\Component\Encryption;

use Jose\Component\Core\AlgorithmManagerFactory;
use Jose\Component\Encryption\Compression\CompressionMethodManagerFactory;

class JWEBuilderFactory
{
    public function __construct(
        private readonly AlgorithmManagerFactory $algorithmManagerFactory,
        private readonly CompressionMethodManagerFactory $compressionMethodManagerFactory
    ) {
    }

    /**
     * Creates a JWE Builder object using the given key encryption algorithms, content encryption algorithms and
     * compression methods.
     *
     * @param string[] $keyEncryptionAlgorithms
     * @param string[] $contentEncryptionAlgorithm
     * @param string[] $compressionMethods
     */
    public function create(
        array $keyEncryptionAlgorithms,
        array $contentEncryptionAlgorithm,
        array $compressionMethods
    ): JWEBuilder {
        $keyEncryptionAlgorithmManager = $this->algorithmManagerFactory->create($keyEncryptionAlgorithms);
        $contentEncryptionAlgorithmManager = $this->algorithmManagerFactory->create($contentEncryptionAlgorithm);
        $compressionMethodManager = $this->compressionMethodManagerFactory->create($compressionMethods);

        return new JWEBuilder(
            $keyEncryptionAlgorithmManager,
            $contentEncryptionAlgorithmManager,
            $compressionMethodManager
        );
    }
}
