<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Event;

use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\JWS;
use Symfony\Contracts\EventDispatcher\Event;

final class JWSLoadingSuccessEvent extends Event
{
    public function __construct(
        private readonly string $token,
        private readonly JWS $jws,
        private readonly JWKSet $JWKSet,
        private readonly int $signature
    ) {
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
