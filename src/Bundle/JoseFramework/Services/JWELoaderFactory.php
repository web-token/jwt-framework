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

    public function create(
        array $serializers,
        array $keyEncryptionAlgorithms,
        array $contentEncryptionAlgorithms,
        array $compressionMethods,
        array $headerCheckers = []
    ): JWELoader {
        $serializerManager = $this->jweSerializerManagerFactory->create($serializers);
        $jweDecrypter = $this->jweDecrypterFactory->create(
            $keyEncryptionAlgorithms,
            $contentEncryptionAlgorithms,
            $compressionMethods
        );
        if ($this->headerCheckerManagerFactory !== null) {
            $headerCheckerManager = $this->headerCheckerManagerFactory->create($headerCheckers);
        } else {
            $headerCheckerManager = null;
        }

        return new JWELoader($serializerManager, $jweDecrypter, $headerCheckerManager, $this->eventDispatcher);
    }
}
