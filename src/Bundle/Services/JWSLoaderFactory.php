<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Services;

use Jose\Component\Signature\JWSTokenSupport;
use Jose\Component\Signature\Serializer\JWSSerializerManagerFactory;
use Psr\EventDispatcher\EventDispatcherInterface;
use function func_get_arg;
use function func_num_args;
use function trigger_deprecation;

final readonly class JWSLoaderFactory
{
    public function __construct(
        private JWSSerializerManagerFactory $jwsSerializerManagerFactory,
        private JWSVerifierFactory $jwsVerifierFactory,
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
                JWSTokenSupport::class
            );
        }
    }

    /**
     * Creates a JWSLoader using the given serializer aliases, signature algorithm aliases and (optionally) the header
     * checker aliases.
     *
     * A fourth argument sets the maximum number of signatures of a token, passed to the loader. It is read with
     * func_num_args()/func_get_arg(3) until 5.0.0.
     */
    public function create(array $serializers, array $algorithms, array $headerCheckers = []): JWSLoader
    {
        $serializerManager = $this->jwsSerializerManagerFactory->create($serializers);
        $jwsVerifier = $this->jwsVerifierFactory->create($algorithms);
        if ($this->headerCheckerManagerFactory !== null) {
            $headerCheckerManager = $this->headerCheckerManagerFactory->create($headerCheckers);
        } else {
            $headerCheckerManager = null;
        }

        return new JWSLoader(
            $serializerManager,
            $jwsVerifier,
            $headerCheckerManager,
            $this->eventDispatcher,
            func_num_args() > 3 ? func_get_arg(3) : null
        );
    }
}
