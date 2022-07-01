<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Event;

use Jose\Component\Signature\JWS;
use Symfony\Contracts\EventDispatcher\Event;

final class JWSBuiltSuccessEvent extends Event
{
    public function __construct(
        private readonly JWS $jws
    ) {
    }

    public function getJws(): JWS
    {
        return $this->jws;
    }
}
