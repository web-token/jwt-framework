<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Event;

use Symfony\Contracts\EventDispatcher\Event;

final class NestedTokenIssuedEvent extends Event
{
    public function __construct(
        private readonly string $nestedToken
    ) {
    }

    public function getNestedToken(): string
    {
        return $this->nestedToken;
    }
}
