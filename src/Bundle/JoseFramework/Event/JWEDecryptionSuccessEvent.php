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
use Jose\Component\Encryption\JWE;
use Symfony\Contracts\EventDispatcher\Event;

final class JWEDecryptionSuccessEvent extends Event
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
     * @var JWK
     */
    private $JWK;

    /**
     * @var int
     */
    private $recipient;

    public function __construct(JWE $jwe, JWKSet $JWKSet, JWK $JWK, int $recipient)
    {
        $this->jwe = $jwe;
        $this->JWKSet = $JWKSet;
        $this->JWK = $JWK;
        $this->recipient = $recipient;
    }

    public function getJws(): JWE
    {
        return $this->jwe;
    }

    public function getJWKSet(): JWKSet
    {
        return $this->JWKSet;
    }

    public function getJWK(): JWK
    {
        return $this->JWK;
    }

    public function getRecipient(): int
    {
        return $this->recipient;
    }
}
