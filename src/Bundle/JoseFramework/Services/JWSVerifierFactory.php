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

final class JWSVerifierFactory
{
    /**
     * @var EventDispatcherInterface
     */
    private $eventDispatcher;

    /**
     * @var AlgorithmManagerFactory
     */
    private $algorithmManagerFactory;

    public function __construct(AlgorithmManagerFactory $algorithmManagerFactory, EventDispatcherInterface $eventDispatcher)
    {
        $this->algorithmManagerFactory = $algorithmManagerFactory;
        $this->eventDispatcher = $eventDispatcher;
    }

    public function create(array $algorithms): JWSVerifier
    {
        $algorithmManager = $this->algorithmManagerFactory->create($algorithms);

        return new JWSVerifier($algorithmManager, $this->eventDispatcher);
    }
}
