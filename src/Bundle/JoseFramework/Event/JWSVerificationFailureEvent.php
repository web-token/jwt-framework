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

namespace Jose\Bundle\JoseFramework\Event;

use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\JWS;
use Symfony\Component\EventDispatcher\Event;

final class JWSVerificationFailureEvent extends Event
{
    private $JWKSet;

    private $detachedPayload;

    private $jws;

    public function __construct(JWS $jws, JWKSet $JWKSet, ?string $detachedPayload)
    {
        $this->JWKSet = $JWKSet;
        $this->detachedPayload = $detachedPayload;
        $this->jws = $jws;
    }

    public function getJws(): JWS
    {
        return $this->jws;
    }

    public function getJWKSet(): JWKSet
    {
        return $this->JWKSet;
    }

    public function getDetachedPayload(): ?string
    {
        return $this->detachedPayload;
    }
}
