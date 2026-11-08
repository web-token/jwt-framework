<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Services;

use Jose\Component\Encryption\JWELoader as BaseJWELoader;
use Jose\Component\Encryption\Serializer\JWESerializerManagerFactory;
use Psr\EventDispatcher\EventDispatcherInterface;

final readonly class JWELoaderFactory
{
    public function __construct(
        private JWESerializerManagerFactory $jweSerializerManagerFactory,
        private JWEDecrypterFactory $jweDecrypterFactory,
        private HeaderCheckerManagerFactory $headerCheckerManagerFactory,
        private EventDispatcherInterface $eventDispatcher
    ) {
    }

    /**
     * The maximum number of recipients is passed to the loader.
     *
     * @param array<string> $serializers
     * @param array<string> $encryptionAlgorithms
     * @param array<string> $headerCheckers
     */
    public function create(
        array $serializers,
        array $encryptionAlgorithms,
        array $headerCheckers = [],
        int $maxRecipients = BaseJWELoader::DEFAULT_MAX_RECIPIENTS
    ): JWELoader {
        $serializerManager = $this->jweSerializerManagerFactory->create($serializers);
        $jweDecrypter = $this->jweDecrypterFactory->create($encryptionAlgorithms);
        $headerCheckerManager = $this->headerCheckerManagerFactory->create($headerCheckers);

        return new JWELoader(
            $serializerManager,
            $jweDecrypter,
            $headerCheckerManager,
            $this->eventDispatcher,
            $maxRecipients
        );
    }
}
