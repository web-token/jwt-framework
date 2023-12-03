<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Event;

use Jose\Component\Encryption\JWE;
use Symfony\Contracts\EventDispatcher\Event;

final class JWEBuiltSuccessEvent extends Event
{
    public function __construct(
        private readonly JWE $jwe
    ) {
    }

    public function getJwe(): JWE
    {
        return $this->jwe;
    }
}
