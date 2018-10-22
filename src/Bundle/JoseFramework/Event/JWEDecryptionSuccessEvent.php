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

final class JWEDecryptionSuccessEvent extends Event
{
    private $jwe;

    private $JWKSet;

    private $recipient;

    public function __construct(JWE $jwe, JWKSet $JWKSet, int $recipient)
    {
        $this->jwe = $jwe;
        $this->JWKSet = $JWKSet;
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

    public function getRecipient(): int
    {
        return $this->recipient;
    }
}
