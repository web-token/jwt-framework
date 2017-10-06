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

use Jose\Component\Checker\HeaderCheckerManagerFactory;
use Jose\Component\Core\AlgorithmManagerFactory;
use Jose\Component\Signature\Serializer\JWSSerializerManagerFactory;

/**
 * Class JWSLoaderFactory.
 */
final class JWSLoaderFactory
{
    /**
     * @var AlgorithmManagerFactory
     */
    private $algorithmManagerFactory;

    /**
     * @var HeaderCheckerManagerFactory
     */
    private $headerCheckerManagerFactory;

    /**
     * @var JWSSerializerManagerFactory
     */
    private $serializerManagerFactory;

    /**
     * JWSLoaderFactory constructor.
     *
     * @param AlgorithmManagerFactory     $algorithmManagerFactory
     * @param HeaderCheckerManagerFactory $headerCheckerManagerFactory
     * @param JWSSerializerManagerFactory $serializerManagerFactory
     */
    public function __construct(AlgorithmManagerFactory $algorithmManagerFactory, HeaderCheckerManagerFactory $headerCheckerManagerFactory, JWSSerializerManagerFactory $serializerManagerFactory)
    {
        $this->algorithmManagerFactory = $algorithmManagerFactory;
        $this->headerCheckerManagerFactory = $headerCheckerManagerFactory;
        $this->serializerManagerFactory = $serializerManagerFactory;
    }

    /**
     * @param string[] $algorithms
     * @param string[] $headerCheckers
     * @param string[] $serializers
     *
     * @return JWSLoader
     */
    public function create(array $algorithms, array $headerCheckers, array $serializers): JWSLoader
    {
        $algorithmManager = $this->algorithmManagerFactory->create($algorithms);
        $headerCheckerManager = $this->headerCheckerManagerFactory->create($headerCheckers);
        $serializerManager = $this->serializerManagerFactory->create($serializers);

        return new JWSLoader($algorithmManager, $headerCheckerManager, $serializerManager);
    }
}
