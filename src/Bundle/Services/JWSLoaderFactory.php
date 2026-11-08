<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Services;

use Jose\Component\Signature\JWSLoader as BaseJWSLoader;
use Jose\Component\Signature\Serializer\JWSSerializerManagerFactory;
use Psr\EventDispatcher\EventDispatcherInterface;

final readonly class JWSLoaderFactory
{
    public function __construct(
        private JWSSerializerManagerFactory $jwsSerializerManagerFactory,
        private JWSVerifierFactory $jwsVerifierFactory,
        private HeaderCheckerManagerFactory $headerCheckerManagerFactory,
        private EventDispatcherInterface $eventDispatcher
    ) {
    }

    /**
     * Creates a JWSLoader using the given serializer aliases, signature algorithm aliases and (optionally) the header
     * checker aliases.
     *
     * The maximum number of signatures is passed to the loader.
     */
    public function create(
        array $serializers,
        array $algorithms,
        array $headerCheckers = [],
        int $maxSignatures = BaseJWSLoader::DEFAULT_MAX_SIGNATURES
    ): JWSLoader {
        $serializerManager = $this->jwsSerializerManagerFactory->create($serializers);
        $jwsVerifier = $this->jwsVerifierFactory->create($algorithms);
        $headerCheckerManager = $this->headerCheckerManagerFactory->create($headerCheckers);

        return new JWSLoader(
            $serializerManager,
            $jwsVerifier,
            $headerCheckerManager,
            $this->eventDispatcher,
            $maxSignatures
        );
    }
}
