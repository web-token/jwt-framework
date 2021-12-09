<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Event;

use Jose\Component\Core\JWT;
use Symfony\Contracts\EventDispatcher\Event;
use Throwable;

final class HeaderCheckedFailureEvent extends Event
{
    /**
     * @var array
     */
    private $mandatoryHeaderParameters;

    public function __construct(
        private JWT $jwt,
        private int $index,
        array $mandatoryHeaderParameters,
        private Throwable $throwable
    ) {
        $this->mandatoryHeaderParameters = $mandatoryHeaderParameters;
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
