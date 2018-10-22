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

use Jose\Bundle\JoseFramework\Event\Events;
use Jose\Bundle\JoseFramework\Event\JWEBuiltEvent;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\Converter\JsonConverter;
use Jose\Component\Encryption\Compression\CompressionMethodManager;
use Jose\Component\Encryption\JWE;
use Jose\Component\Encryption\JWEBuilder as BaseJWEBuilder;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;

final class JWEBuilder extends BaseJWEBuilder
{
    private $eventDispatcher;

    public function __construct(JsonConverter $jsonConverter, AlgorithmManager $keyEncryptionAlgorithmManager, AlgorithmManager $contentEncryptionAlgorithmManager, CompressionMethodManager $compressionManager, EventDispatcherInterface $eventDispatcher)
    {
        parent::__construct($jsonConverter, $keyEncryptionAlgorithmManager, $contentEncryptionAlgorithmManager, $compressionManager);
        $this->eventDispatcher = $eventDispatcher;
    }

    public function build(): JWE
    {
        $jws = parent::build();
        $this->eventDispatcher->dispatch(Events::JWE_BUILT, new JWEBuiltEvent($jws));

        return $jws;
    }
}
