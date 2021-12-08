<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Event;

use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Encryption\JWE;
use Symfony\Contracts\EventDispatcher\Event;

final class JWEDecryptionSuccessEvent extends Event
{
    public function __construct(
        private JWE $jwe,
        private JWKSet $JWKSet,
        private JWK $JWK,
        private int $recipient
    ) {
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
