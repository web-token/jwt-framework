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

use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\JWS;
use Symfony\Contracts\EventDispatcher\Event;

final class JWSLoadingSuccessEvent extends Event
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
     * @var int
     */
    private $signature;

    /**
     * @var string
     */
    private $token;

    public function __construct(string $token, JWS $jws, JWKSet $JWKSet, int $signature)
    {
        $this->jws = $jws;
        $this->JWKSet = $JWKSet;
        $this->signature = $signature;
        $this->token = $token;
    }

    public function getJws(): JWS
    {
        return $this->jws;
    }

    public function getToken(): string
    {
        return $this->token;
    }

    public function getJWKSet(): JWKSet
    {
        return $this->JWKSet;
    }

    public function getSignature(): int
    {
        return $this->signature;
    }
}
