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
use Jose\Component\Encryption\JWE;
use Symfony\Contracts\EventDispatcher\Event;

final class JWELoadingSuccessEvent extends Event
{
    /**
     * @var JWE
     */
    private $jwe;

    /**
     * @var JWKSet
     */
    private $JWKSet;

    /**
     * @var int
     */
    private $recipient;

    /**
     * @var string
     */
    private $token;

    public function __construct(string $token, JWE $jwe, JWKSet $JWKSet, int $recipient)
    {
        $this->jwe = $jwe;
        $this->JWKSet = $JWKSet;
        $this->recipient = $recipient;
        $this->token = $token;
    }

    public function getJws(): JWE
    {
        return $this->jwe;
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
