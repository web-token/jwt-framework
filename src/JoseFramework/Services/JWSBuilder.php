<?php

declare(strict_types=1);

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
    public function __construct(
        AlgorithmManager $signatureAlgorithmManager,
        private readonly EventDispatcherInterface $eventDispatcher
    ) {
        parent::__construct($signatureAlgorithmManager);
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
