<?php

declare(strict_types=1);

namespace Jose\Component\Encryption;

use Jose\Component\Checker\HeaderCheckerManagerFactory;
use Jose\Component\Core\Exception\InvalidArgumentException;
use Jose\Component\Encryption\Serializer\JWESerializerManagerFactory;
use function trigger_deprecation;

readonly class JWELoaderFactory
{
    public function __construct(
        private JWESerializerManagerFactory $jweSerializerManagerFactory,
        private JWEDecrypterFactory $jweDecrypterFactory,
        private ?HeaderCheckerManagerFactory $headerCheckerManagerFactory
    ) {
        if ($headerCheckerManagerFactory === null) {
            trigger_deprecation(
                'web-token/jwt-library',
                '4.3.0',
                'Creating a "%s" without a header checker manager factory is deprecated and will not be possible in 5.0.0: the loaders it creates check no header parameter, not even those listed in "crit". Pass a "%s" that has the "%s" token type support.',
                static::class,
                HeaderCheckerManagerFactory::class,
                JWETokenSupport::class
            );
        }
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
        if ($this->headerCheckerManagerFactory !== null) {
            $headerCheckerManager = $this->headerCheckerManagerFactory->create($headerCheckers);
        } elseif ($headerCheckers !== []) {
            throw new InvalidArgumentException(
                'Header checkers were requested, but no header checker manager factory is available.'
            );
        } else {
            $headerCheckerManager = null;
        }

        return new JWELoader(
            $serializerManager,
            $jweDecrypter,
            $headerCheckerManager,
            $maxRecipients
        );
    }
}
