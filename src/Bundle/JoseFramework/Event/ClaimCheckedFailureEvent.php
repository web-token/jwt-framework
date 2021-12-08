<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Event;

use Symfony\Contracts\EventDispatcher\Event;
use Throwable;

final class ClaimCheckedFailureEvent extends Event
{
    /**
     * @var array
     */
    private $claims;

    /**
     * @var array
     */
    private $mandatoryClaims;

    public function __construct(
        array $claims,
        array $mandatoryClaims,
        private Throwable $throwable
    ) {
        $this->claims = $claims;
        $this->mandatoryClaims = $mandatoryClaims;
    }

    public function getClaims(): array
    {
        return $this->claims;
    }

    public function getMandatoryClaims(): array
    {
        return $this->mandatoryClaims;
    }

    public function getThrowable(): Throwable
    {
        return $this->throwable;
    }
}
