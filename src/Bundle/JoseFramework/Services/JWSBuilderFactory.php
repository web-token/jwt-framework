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

namespace Jose\Bundle\JoseFramework\Services;

use Jose\Component\Core\AlgorithmManagerFactory;
use Jose\Component\Core\Converter\JsonConverter;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;

final class JWSBuilderFactory
{
    private $eventDispatcher;

    private $jsonEncoder;

    private $signatureAlgorithmManagerFactory;

    public function __construct(JsonConverter $jsonEncoder, AlgorithmManagerFactory $signatureAlgorithmManagerFactory, EventDispatcherInterface $eventDispatcher)
    {
        $this->jsonEncoder = $jsonEncoder;
        $this->signatureAlgorithmManagerFactory = $signatureAlgorithmManagerFactory;
        $this->eventDispatcher = $eventDispatcher;
    }

    /**
     * This method creates a JWSBuilder using the given algorithm aliases.
     *
     * @param string[] $algorithms
     */
    public function create(array $algorithms): JWSBuilder
    {
        $algorithmManager = $this->signatureAlgorithmManagerFactory->create($algorithms);

        return new JWSBuilder($this->jsonEncoder, $algorithmManager, $this->eventDispatcher);
    }
}
