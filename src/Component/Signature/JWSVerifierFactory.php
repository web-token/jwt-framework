<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Signature;

use Jose\Component\Core\AlgorithmManagerFactory;

/**
 * Class JWSVerifierFactory.
 */
final class JWSVerifierFactory
{
    /**
     * @var AlgorithmManagerFactory
     */
    private $algorithmManagerFactory;

    /**
     * JWSVerifierFactory constructor.
     *
     * @param AlgorithmManagerFactory $algorithmManagerFactory
     */
    public function __construct(AlgorithmManagerFactory $algorithmManagerFactory)
    {
        $this->algorithmManagerFactory = $algorithmManagerFactory;
    }

    /**
     * @param string[] $algorithms
     *
     * @return JWSVerifier
     */
    public function create(array $algorithms): JWSVerifier
    {
        $algorithmManager = $this->algorithmManagerFactory->create($algorithms);

        return new JWSVerifier($algorithmManager);
    }
}
