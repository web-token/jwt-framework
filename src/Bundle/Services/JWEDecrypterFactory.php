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
     * @param array<string> $encryptionAlgorithms
     * @param null|array<string> $contentEncryptionAlgorithms
     * @param null|array<string> $compressionMethods
     */
    public function create(
        array $encryptionAlgorithms,
        null|array $contentEncryptionAlgorithms = null,
        null|array $compressionMethods = null
    ): JWEDecrypter {
        if ($contentEncryptionAlgorithms !== null) {
            trigger_deprecation(
                'web-token/jwt-library',
                '3.3.0',
                'The parameter "$contentEncryptionAlgorithms" is deprecated and will be removed in 4.0.0. Please set all algorithms in the first argument and set "null" instead.'
            );
            $encryptionAlgorithms = array_merge($encryptionAlgorithms, $contentEncryptionAlgorithms);
        }

        $encryptionAlgorithmManager = $this->algorithmManagerFactory->create($encryptionAlgorithms);
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

        return new JWEDecrypter(
            $encryptionAlgorithmManager,
            null,
            $compressionMethodManager,
            $this->eventDispatcher
        );
    }
}
