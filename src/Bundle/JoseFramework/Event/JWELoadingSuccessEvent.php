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
use Jose\Component\Encryption\JWE;
use Symfony\Component\EventDispatcher\Event;

final class JWELoadingSuccessEvent extends Event
{
    private $jws;

    private $JWKSet;

    private $recipient;

    private $token;

    public function __construct(string $token, JWE $jws, JWKSet $JWKSet, int $recipient)
    {
        $this->jws = $jws;
        $this->JWKSet = $JWKSet;
        $this->recipient = $recipient;
        $this->token = $token;
    }

    public function getJws(): JWE
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

    public function getRecipient(): int
    {
        return $this->recipient;
    }
}
