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

use Jose\Bundle\JoseFramework\Event\JWSBuiltFailureEvent;
use Jose\Bundle\JoseFramework\Event\JWSBuiltSuccessEvent;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSBuilder as BaseJWSBuilder;
use Psr\EventDispatcher\EventDispatcherInterface;
use Throwable;

final class JWSBuilder extends BaseJWSBuilder
{
    /**
     * @var EventDispatcherInterface
     */
    private $eventDispatcher;

    public function __construct(AlgorithmManager $signatureAlgorithmManager, EventDispatcherInterface $eventDispatcher)
    {
        parent::__construct($signatureAlgorithmManager);
        $this->eventDispatcher = $eventDispatcher;
    }

    public function build(): JWS
    {
        try {
            $jws = parent::build();
            $this->eventDispatcher->dispatch(new JWSBuiltSuccessEvent($jws));

            return $jws;
        } catch (Throwable $throwable) {
            $this->eventDispatcher->dispatch(new JWSBuiltFailureEvent(
                $this->payload,
                $this->signatures,
                $this->isPayloadDetached,
                $this->isPayloadEncoded,
                $throwable
            ));

            throw $throwable;
        }
    }
}
