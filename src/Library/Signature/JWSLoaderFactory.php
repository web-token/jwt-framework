<?php

declare(strict_types=1);

namespace Jose\Component\Signature;

use Jose\Component\Checker\HeaderCheckerManagerFactory;
use Jose\Component\Signature\Serializer\JWSSerializerManagerFactory;
use function func_get_arg;
use function func_num_args;

class JWSLoaderFactory
{
    public function __construct(
        private readonly JWSSerializerManagerFactory $jwsSerializerManagerFactory,
        private readonly JWSVerifierFactory $jwsVerifierFactory,
        private readonly ?HeaderCheckerManagerFactory $headerCheckerManagerFactory
    ) {
    }

    /**
     * Creates a JWSLoader using the given serializer aliases, signature algorithm aliases and (optionally) the header
     * checker aliases.
     *
     * A fourth argument sets the maximum number of signatures of a token, passed to the loader. That argument is not
     * part of the signature yet (it will be in 5.0.0) and is read with func_num_args()/func_get_arg(3), so that classes
     * extending this one remain compatible.
     *
     * @param array<string> $serializers
     * @param array<string> $algorithms
     * @param array<string> $headerCheckers
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
            func_num_args() > 3 ? func_get_arg(3) : null
        );
    }
}
