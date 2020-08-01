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

use Psr\EventDispatcher\EventDispatcherInterface;

final class NestedTokenLoaderFactory
{
    /**
     * @var EventDispatcherInterface
     */
    private $eventDispatcher;

    /**
     * @var JWELoaderFactory
     */
    private $jweLoaderFactory;

    /**
     * @var JWSLoaderFactory
     */
    private $jwsLoaderFactory;

    public function __construct(JWELoaderFactory $jweLoaderFactory, JWSLoaderFactory $jwsLoaderFactory, EventDispatcherInterface $eventDispatcher)
    {
        $this->jweLoaderFactory = $jweLoaderFactory;
        $this->jwsLoaderFactory = $jwsLoaderFactory;
        $this->eventDispatcher = $eventDispatcher;
    }

    public function create(array $jweSerializers, array $keyEncryptionAlgorithms, array $contentEncryptionAlgorithms, array $compressionMethods, array $jweHeaderCheckers, array $jwsSerializers, array $signatureAlgorithms, array $jwsHeaderCheckers): NestedTokenLoader
    {
        $jweLoader = $this->jweLoaderFactory->create($jweSerializers, $keyEncryptionAlgorithms, $contentEncryptionAlgorithms, $compressionMethods, $jweHeaderCheckers);
        $jwsLoader = $this->jwsLoaderFactory->create($jwsSerializers, $signatureAlgorithms, $jwsHeaderCheckers);

        return new NestedTokenLoader($jweLoader, $jwsLoader, $this->eventDispatcher);
    }
}
