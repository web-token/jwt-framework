<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Event;

use Symfony\Contracts\EventDispatcher\Event;

final class ClaimCheckedSuccessEvent extends Event
{
    public function __construct(
        private readonly array $claims,
        private readonly array $mandatoryClaims,
        private readonly array $checkedClaims
    ) {
    }

    public function getClaims(): array
    {
        return $this->claims;
    }

    public function getMandatoryClaims(): array
    {
        return $this->mandatoryClaims;
    }

    public function getCheckedClaims(): array
    {
        return $this->checkedClaims;
    }
}
