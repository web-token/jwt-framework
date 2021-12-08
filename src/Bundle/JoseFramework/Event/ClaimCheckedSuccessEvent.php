<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Event;

use Symfony\Contracts\EventDispatcher\Event;

final class ClaimCheckedSuccessEvent extends Event
{
    /**
     * @var array
     */
    private $claims;

    /**
     * @var array
     */
    private $mandatoryClaims;

    /**
     * @var array
     */
    private $checkedClaims;

    public function __construct(array $claims, array $mandatoryClaims, array $checkedClaims)
    {
        $this->claims = $claims;
        $this->mandatoryClaims = $mandatoryClaims;
        $this->checkedClaims = $checkedClaims;
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
