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

use Jose\Component\Core\AlgorithmManagerFactory;
use Psr\EventDispatcher\EventDispatcherInterface;

final class JWSBuilderFactory
{
    /**
     * @var EventDispatcherInterface
     */
    private $eventDispatcher;

    /**
     * @var AlgorithmManagerFactory
     */
    private $signatureAlgorithmManagerFactory;

    public function __construct(AlgorithmManagerFactory $signatureAlgorithmManagerFactory, EventDispatcherInterface $eventDispatcher)
    {
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

        return new JWSBuilder($algorithmManager, $this->eventDispatcher);
    }
}
