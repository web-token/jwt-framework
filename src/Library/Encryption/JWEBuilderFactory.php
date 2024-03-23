<?php

declare(strict_types=1);

namespace Jose\Component\Encryption;

use Jose\Component\Core\AlgorithmManagerFactory;
use Jose\Component\Encryption\Compression\CompressionMethodManagerFactory;

class JWEBuilderFactory
{
    public function __construct(
        private readonly AlgorithmManagerFactory $algorithmManagerFactory,
    ) {
    }

    /**
     * Creates a JWE Builder object using the given key encryption algorithms, content encryption algorithms and
     * compression methods.
     *
     * @param string[] $keyEncryptionAlgorithms
     */
    public function create(
        array $keyEncryptionAlgorithms,
    ): JWEBuilder {
        $algorithmManager = $this->algorithmManagerFactory->create($keyEncryptionAlgorithms);

        return new JWEBuilder($algorithmManager);
    }
}
