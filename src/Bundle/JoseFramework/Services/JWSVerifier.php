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
use Jose\Bundle\JoseFramework\Event\JWSVerificationFailureEvent;
use Jose\Bundle\JoseFramework\Event\JWSVerificationSuccessEvent;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSVerifier as BaseJWSVerifier;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;

final class JWSVerifier extends BaseJWSVerifier
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

    public function verifyWithKeySet(JWS $jws, JWKSet $jwkset, int $signatureIndex, ?string $detachedPayload = null, JWK &$jwk = null): bool
    {
        $success = parent::verifyWithKeySet($jws, $jwkset, $signatureIndex, $detachedPayload, $jwk);
        if ($success) {
            $this->eventDispatcher->dispatch(Events::JWS_VERIFICATION_SUCCESS, new JWSVerificationSuccessEvent(
                $jws,
                $jwkset,
                $signatureIndex,
                $detachedPayload,
                $jwk
            ));
        } else {
            $this->eventDispatcher->dispatch(Events::JWS_VERIFICATION_FAILURE, new JWSVerificationFailureEvent(
                $jws,
                $jwkset,
                $detachedPayload
            ));
        }

        return $success;
    }
}
