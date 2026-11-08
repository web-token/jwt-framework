<?php

declare(strict_types=1);

namespace Jose\Component\Signature;

use Jose\Component\Checker\HeaderCheckerManagerFactory;
use Jose\Component\Core\Exception\InvalidArgumentException;
use Jose\Component\Signature\Serializer\JWSSerializerManagerFactory;
use function trigger_deprecation;

class JWSLoaderFactory
{
    public function __construct(
        private readonly JWSSerializerManagerFactory $jwsSerializerManagerFactory,
        private readonly JWSVerifierFactory $jwsVerifierFactory,
        private readonly ?HeaderCheckerManagerFactory $headerCheckerManagerFactory
    ) {
        if ($headerCheckerManagerFactory === null) {
            trigger_deprecation(
                'web-token/jwt-library',
                '4.3.0',
                'Creating a "%s" without a header checker manager factory is deprecated and will not be possible in 5.0.0: the loaders it creates check no header parameter, not even those listed in "crit". Pass a "%s" that has the "%s" token type support.',
                static::class,
                HeaderCheckerManagerFactory::class,
                JWSTokenSupport::class
            );
        }
    }

    /**
     * Creates a JWSLoader using the given serializer aliases, signature algorithm aliases and (optionally) the header
     * checker aliases.
     *
     * The maximum number of signatures is passed to the loader.
     *
     * @param array<string> $serializers
     * @param array<string> $algorithms
     * @param array<string> $headerCheckers
     */
    public function create(
        array $serializers,
        array $algorithms,
        array $headerCheckers = [],
        int $maxSignatures = JWSLoader::DEFAULT_MAX_SIGNATURES
    ): JWSLoader {
        $serializerManager = $this->jwsSerializerManagerFactory->create($serializers);
        $jwsVerifier = $this->jwsVerifierFactory->create($algorithms);
        if ($this->headerCheckerManagerFactory !== null) {
            $headerCheckerManager = $this->headerCheckerManagerFactory->create($headerCheckers);
        } elseif ($headerCheckers !== []) {
            throw new InvalidArgumentException(
                'Header checkers were requested, but no header checker manager factory is available.'
            );
        } else {
            $headerCheckerManager = null;
        }

        return new JWSLoader(
            $serializerManager,
            $jwsVerifier,
            $headerCheckerManager,
            $maxSignatures
        );
    }
}
