<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Signature;

use Jose\Component\Checker\HeaderCheckerManagerFactory;
use Jose\Component\Signature\Serializer\JWSSerializerManagerFactory;

class JWSLoaderFactory
{
    /**
     * @var JWSVerifierFactory
     */
    private $jwsVerifierFactory;

    /**
     * @var JWSSerializerManagerFactory
     */
    private $jwsSerializerManagerFactory;

    /**
     * @var HeaderCheckerManagerFactory|null
     */
    private $headerCheckerManagerFactory = null;

    /**
     * JWSLoaderFactory constructor.
     *
     * @param JWSSerializerManagerFactory      $jwsSerializerManagerFactory
     * @param JWSVerifierFactory               $jwsVerifierFactory
     * @param HeaderCheckerManagerFactory|null $headerCheckerManagerFactory
     */
    public function __construct(JWSSerializerManagerFactory $jwsSerializerManagerFactory, JWSVerifierFactory $jwsVerifierFactory, ?HeaderCheckerManagerFactory $headerCheckerManagerFactory)
    {
        $this->jwsSerializerManagerFactory = $jwsSerializerManagerFactory;
        $this->jwsVerifierFactory = $jwsVerifierFactory;
        $this->headerCheckerManagerFactory = $headerCheckerManagerFactory;
    }

    /**
     * Creates a JWSLoader using the given serializer aliases, signature algorithm aliases and (optionally)
     * the header checker aliases.
     *
     * @param array $serializers
     * @param array $algorithms
     * @param array $headerCheckers
     *
     * @return JWSLoader
     */
    public function create(array $serializers, array $algorithms, array $headerCheckers = []): JWSLoader
    {
        $serializerManager = $this->jwsSerializerManagerFactory->create($serializers);
        $jwsVerifier = $this->jwsVerifierFactory->create($algorithms);
        if (null !== $this->headerCheckerManagerFactory) {
            $headerCheckerManager = $this->headerCheckerManagerFactory->create($headerCheckers);
        } else {
            $headerCheckerManager = null;
        }

        return new JWSLoader($serializerManager, $jwsVerifier, $headerCheckerManager);
    }
}
