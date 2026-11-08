<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Services;

use Jose\Component\Core\Exception\InvalidArgumentException;
use Jose\Component\Encryption\JWELoader as BaseJWELoader;
use Jose\Component\Encryption\JWETokenSupport;
use Jose\Component\Encryption\Serializer\JWESerializerManagerFactory;
use Psr\EventDispatcher\EventDispatcherInterface;
use function trigger_deprecation;

final readonly class JWELoaderFactory
{
    public function __construct(
        private JWESerializerManagerFactory $jweSerializerManagerFactory,
        private JWEDecrypterFactory $jweDecrypterFactory,
        private ?HeaderCheckerManagerFactory $headerCheckerManagerFactory,
        private EventDispatcherInterface $eventDispatcher
    ) {
        if ($headerCheckerManagerFactory === null) {
            trigger_deprecation(
                'web-token/jwt-framework',
                '4.3.0',
                'Creating a "%s" without a header checker manager factory is deprecated and will not be possible in 5.0.0: the loaders it creates check no header parameter, not even those listed in "crit". Pass a "%s" that has the "%s" token type support.',
                self::class,
                HeaderCheckerManagerFactory::class,
                JWETokenSupport::class
            );
        }
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
            $this->eventDispatcher,
            $maxRecipients
        );
    }
}
