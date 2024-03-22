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
        private readonly null|CompressionMethodManagerFactory $compressionMethodManagerFactory,
        private readonly EventDispatcherInterface $eventDispatcher
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
     * This method creates a JWEBuilder using the given algorithm aliases.
     *
     * @param string[] $keyEncryptionAlgorithms
     * @param string[] $contentEncryptionAlgorithms
     * @param null|string[] $compressionMethods
     */
    public function create(
        array $keyEncryptionAlgorithms,
        array $contentEncryptionAlgorithms,
        null|array $compressionMethods = null
    ): JWEBuilder {
        $algorithmManager = $this->algorithmManagerFactory->create(
            array_merge($keyEncryptionAlgorithms, $contentEncryptionAlgorithms)
        );
        if ($compressionMethods !== null) {
            trigger_deprecation(
                'web-token/jwt-library',
                '3.3.0',
                'The parameter "$compressionMethods" is deprecated and will be removed in 4.0.0. Compression is not recommended for JWE. Please set "null" instead.'
            );
        }
        $compressionMethodManager = $compressionMethods === null ? null : $this->compressionMethodManagerFactory?->create(
            $compressionMethods
        );

        return new JWEBuilder($algorithmManager, null, $compressionMethodManager, $this->eventDispatcher);
    }
}
