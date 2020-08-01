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

namespace Jose\Bundle\JoseFramework\Event;

use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\JWS;
use Symfony\Contracts\EventDispatcher\Event;

final class JWSVerificationSuccessEvent extends Event
{
    /**
     * @var JWS
     */
    private $jws;

    /**
     * @var JWKSet
     */
    private $JWKSet;

    /**
     * @var JWK
     */
    private $JWK;

    /**
     * @var int
     */
    private $signature;

    /**
     * @var null|string
     */
    private $detachedPayload;

    public function __construct(JWS $jws, JWKSet $JWKSet, int $signature, ?string $detachedPayload, JWK $JWK)
    {
        $this->jws = $jws;
        $this->JWKSet = $JWKSet;
        $this->JWK = $JWK;
        $this->signature = $signature;
        $this->detachedPayload = $detachedPayload;
    }

    public function getJws(): JWS
    {
        return $this->jws;
    }

    public function getJWKSet(): JWKSet
    {
        return $this->JWKSet;
    }

    public function getJWK(): JWK
    {
        return $this->JWK;
    }

    public function getSignature(): int
    {
        return $this->signature;
    }

    public function getDetachedPayload(): ?string
    {
        return $this->detachedPayload;
    }
}
