<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Event;

use Jose\Component\Core\JWT;
use Symfony\Contracts\EventDispatcher\Event;
use Throwable;

final class HeaderCheckedFailureEvent extends Event
{
    public function __construct(
        private readonly JWT $jwt,
        private readonly int $index,
        private readonly array $mandatoryHeaderParameters,
        private readonly Throwable $throwable
    ) {
    }

    public function getJwt(): JWT
    {
        return $this->jwt;
    }

    public function getIndex(): int
    {
        return $this->index;
    }

    public function getMandatoryHeaderParameters(): array
    {
        return $this->mandatoryHeaderParameters;
    }

    public function getThrowable(): Throwable
    {
        return $this->throwable;
    }
}
