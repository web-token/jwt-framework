<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Services;

use Jose\Component\Signature\Serializer\JWSSerializerManagerFactory;
use Psr\EventDispatcher\EventDispatcherInterface;
use function func_get_arg;
use function func_num_args;

final readonly class JWSLoaderFactory
{
    public function __construct(
        private JWSSerializerManagerFactory $jwsSerializerManagerFactory,
        private JWSVerifierFactory $jwsVerifierFactory,
        private ?HeaderCheckerManagerFactory $headerCheckerManagerFactory,
        private EventDispatcherInterface $eventDispatcher
    ) {
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
