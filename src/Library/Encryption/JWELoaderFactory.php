<?php

declare(strict_types=1);

namespace Jose\Component\Encryption;

use Jose\Component\Checker\HeaderCheckerManagerFactory;
use Jose\Component\Encryption\Serializer\JWESerializerManagerFactory;

readonly class JWELoaderFactory
{
    public function __construct(
        private JWESerializerManagerFactory $jweSerializerManagerFactory,
        private JWEDecrypterFactory $jweDecrypterFactory,
        private HeaderCheckerManagerFactory $headerCheckerManagerFactory
    ) {
    }

    /**
     * The maximum number of recipients is passed to the loader.
     */
    public function create(
        array $serializers,
        array $encryptionAlgorithms,
        array $headerCheckers = [],
        int $maxRecipients = JWELoader::DEFAULT_MAX_RECIPIENTS
    ): JWELoader {
        $serializerManager = $this->jweSerializerManagerFactory->create($serializers);
        $jweDecrypter = $this->jweDecrypterFactory->create($encryptionAlgorithms);
        $headerCheckerManager = $this->headerCheckerManagerFactory->create($headerCheckers);

        return new JWELoader(
            $serializerManager,
            $jweDecrypter,
            $headerCheckerManager,
            $maxRecipients
        );
    }
}
