<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Services;

use Jose\Component\Encryption\JWETokenSupport;
use Jose\Component\Encryption\Serializer\JWESerializerManagerFactory;
use Psr\EventDispatcher\EventDispatcherInterface;
use function func_get_arg;
use function func_num_args;
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
     * A fourth argument sets the maximum number of recipients of a token, passed to the loader. It is read with
     * func_num_args()/func_get_arg(3) until 5.0.0.
     *
     * @param array<string> $serializers
     * @param array<string> $encryptionAlgorithms
     * @param array<string> $headerCheckers
     */
    public function create(array $serializers, array $encryptionAlgorithms, array $headerCheckers = []): JWELoader
    {
        $serializerManager = $this->jweSerializerManagerFactory->create($serializers);
        $jweDecrypter = $this->jweDecrypterFactory->create($encryptionAlgorithms);
        if ($this->headerCheckerManagerFactory !== null) {
            $headerCheckerManager = $this->headerCheckerManagerFactory->create($headerCheckers);
        } else {
            $headerCheckerManager = null;
        }

        return new JWELoader(
            $serializerManager,
            $jweDecrypter,
            $headerCheckerManager,
            $this->eventDispatcher,
            func_num_args() > 3 ? func_get_arg(3) : null
        );
    }
}
