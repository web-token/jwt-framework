<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Services;

use Jose\Component\Core\AlgorithmManagerFactory;
use Jose\Component\Encryption\Compression\CompressionMethodManagerFactory;
use Psr\EventDispatcher\EventDispatcherInterface;

final class JWEBuilderFactory
{
    public function __construct(
        private readonly AlgorithmManagerFactory $algorithmManagerFactory,
        private readonly CompressionMethodManagerFactory $compressionMethodManagerFactory,
        private readonly EventDispatcherInterface $eventDispatcher
    ) {
    }

    /**
     * This method creates a JWEBuilder using the given algorithm aliases.
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
            $compressionMethodManager,
            $this->eventDispatcher
        );
    }
}
