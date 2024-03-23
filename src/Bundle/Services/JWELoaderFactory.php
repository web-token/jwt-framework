<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Services;

use Jose\Component\Encryption\Serializer\JWESerializerManagerFactory;
use Psr\EventDispatcher\EventDispatcherInterface;

final class JWELoaderFactory
{
    public function __construct(
        private readonly JWESerializerManagerFactory $jweSerializerManagerFactory,
        private readonly JWEDecrypterFactory $jweDecrypterFactory,
        private readonly ?HeaderCheckerManagerFactory $headerCheckerManagerFactory,
        private readonly EventDispatcherInterface $eventDispatcher
    ) {
    }

    /**
     * @param array<string> $serializers
     * @param array<string> $encryptionAlgorithms
     * @param array<string>|null $contentEncryptionAlgorithms
     * @param array<string>|null $compressionMethods
     * @param array<string> $headerCheckers
     */
    public function create(
        array $serializers,
        array $encryptionAlgorithms,
        null|array $contentEncryptionAlgorithms = null,
        null|array $compressionMethods = null,
        array $headerCheckers = []
    ): JWELoader {
        if ($contentEncryptionAlgorithms !== null) {
            trigger_deprecation(
                'web-token/jwt-library',
                '3.3.0',
                'The parameter "$contentEncryptionAlgorithms" is deprecated and will be removed in 4.0.0. Please set "null" instead.'
            );
            $encryptionAlgorithms = array_merge($encryptionAlgorithms, $contentEncryptionAlgorithms);
        }
        $serializerManager = $this->jweSerializerManagerFactory->create($serializers);
        $jweDecrypter = $this->jweDecrypterFactory->create($encryptionAlgorithms, null, $compressionMethods);
        if ($this->headerCheckerManagerFactory !== null) {
            $headerCheckerManager = $this->headerCheckerManagerFactory->create($headerCheckers);
        } else {
            $headerCheckerManager = null;
        }

        return new JWELoader($serializerManager, $jweDecrypter, $headerCheckerManager, $this->eventDispatcher);
    }
}
