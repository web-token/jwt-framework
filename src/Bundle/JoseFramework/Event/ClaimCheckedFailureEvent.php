<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

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

    /**
     * @var Throwable
     */
    private $throwable;

    public function __construct(array $claims, array $mandatoryClaims, Throwable $throwable)
    {
        $this->claims = $claims;
        $this->mandatoryClaims = $mandatoryClaims;
        $this->throwable = $throwable;
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
