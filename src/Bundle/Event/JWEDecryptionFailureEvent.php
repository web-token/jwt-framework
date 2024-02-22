<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Event;

use Jose\Component\Core\JWKSet;
use Jose\Component\Encryption\JWE;
use Symfony\Contracts\EventDispatcher\Event;

final class JWEDecryptionFailureEvent extends Event
{
    public function __construct(
        private readonly JWE $jwe,
        private readonly JWKSet $JWKSet
    ) {
    }

    public function getJWKSet(): JWKSet
    {
        return $this->JWKSet;
    }

    public function getJwe(): JWE
    {
        return $this->jwe;
    }
}
