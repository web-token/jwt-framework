<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2019 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Bundle\JoseFramework\Services;

use Jose\Bundle\JoseFramework\Event\Events;
use Jose\Bundle\JoseFramework\Event\JWSBuiltSuccessEvent;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSBuilder as BaseJWSBuilder;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;

final class JWSBuilder extends BaseJWSBuilder
{
    private $eventDispatcher;

    public function __construct(AlgorithmManager $signatureAlgorithmManager, EventDispatcherInterface $eventDispatcher)
    {
        parent::__construct($signatureAlgorithmManager);
        $this->eventDispatcher = $eventDispatcher;
    }

    public function build(): JWS
    {
        $jws = parent::build();
        $this->eventDispatcher->dispatch(Events::JWS_BUILT_SUCCESS, new JWSBuiltSuccessEvent($jws));

        return $jws;
    }
}
