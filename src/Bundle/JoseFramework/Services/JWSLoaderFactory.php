<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Bundle\JoseFramework\Services;

use Jose\Component\Signature\Serializer\JWSSerializerManagerFactory;
use Psr\EventDispatcher\EventDispatcherInterface;

final class JWSLoaderFactory
{
    /**
     * @var EventDispatcherInterface
     */
    private $eventDispatcher;

    /**
     * @var JWSVerifierFactory
     */
    private $jwsVerifierFactory;

    /**
     * @var JWSSerializerManagerFactory
     */
    private $jwsSerializerManagerFactory;

    /**
     * @var null|HeaderCheckerManagerFactory
     */
    private $headerCheckerManagerFactory;

    public function __construct(JWSSerializerManagerFactory $jwsSerializerManagerFactory, JWSVerifierFactory $jwsVerifierFactory, ?HeaderCheckerManagerFactory $headerCheckerManagerFactory, EventDispatcherInterface $eventDispatcher)
    {
        $this->jwsSerializerManagerFactory = $jwsSerializerManagerFactory;
        $this->jwsVerifierFactory = $jwsVerifierFactory;
        $this->headerCheckerManagerFactory = $headerCheckerManagerFactory;
        $this->eventDispatcher = $eventDispatcher;
    }

    /**
     * Creates a JWSLoader using the given serializer aliases, signature algorithm aliases and (optionally)
     * the header checker aliases.
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

        return new JWSLoader($serializerManager, $jwsVerifier, $headerCheckerManager, $this->eventDispatcher);
    }
}
