<?php

declare(strict_types=1);

namespace Jose\Component\Encryption;

use Jose\Component\Core\AlgorithmManagerFactory;
use Jose\Component\Encryption\Compression\CompressionMethodManagerFactory;

class JWEDecrypterFactory
{
    public function __construct(
        private readonly AlgorithmManagerFactory $algorithmManagerFactory,
        private readonly CompressionMethodManagerFactory $compressionMethodManagerFactory
    ) {
    }

    /**
     * Creates a JWE Decrypter object using the given key encryption algorithms, content encryption algorithms and
     * compression methods.
     *
     * @param string[] $keyEncryptionAlgorithms
     * @param string[] $contentEncryptionAlgorithms
     * @param string[] $compressionMethods
     */
    public function create(
        array $keyEncryptionAlgorithms,
        array $contentEncryptionAlgorithms,
        array $compressionMethods
    ): JWEDecrypter {
        $keyEncryptionAlgorithmManager = $this->algorithmManagerFactory->create($keyEncryptionAlgorithms);
        $contentEncryptionAlgorithmManager = $this->algorithmManagerFactory->create($contentEncryptionAlgorithms);
        $compressionMethodManager = $this->compressionMethodManagerFactory->create($compressionMethods);

        return new JWEDecrypter(
            $keyEncryptionAlgorithmManager,
            $contentEncryptionAlgorithmManager,
            $compressionMethodManager
        );
    }
}
