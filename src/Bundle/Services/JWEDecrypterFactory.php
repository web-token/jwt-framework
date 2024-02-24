<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Services;

use Jose\Component\Core\AlgorithmManagerFactory;
use Jose\Component\Encryption\Compression\CompressionMethodManagerFactory;
use Psr\EventDispatcher\EventDispatcherInterface;

final class JWEDecrypterFactory
{
    public function __construct(
        private readonly AlgorithmManagerFactory $algorithmManagerFactory,
        private readonly CompressionMethodManagerFactory $compressionMethodManagerFactory,
        private readonly EventDispatcherInterface $eventDispatcher
    ) {
    }

    public function create(
        array $keyEncryptionAlgorithms,
        array $contentEncryptionAlgorithms,
        array $compressionMethods
    ): JWEDecrypter {
        $algorithmManager = $this->algorithmManagerFactory->create(array_merge(
            $keyEncryptionAlgorithms,
            $contentEncryptionAlgorithms
        ));
        $compressionMethodManager = $this->compressionMethodManagerFactory->create($compressionMethods);

        return new JWEDecrypter($algorithmManager, $compressionMethodManager, $this->eventDispatcher);
    }
}
