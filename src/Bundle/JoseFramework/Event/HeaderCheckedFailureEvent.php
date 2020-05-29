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

use Jose\Component\Core\JWT;
use Symfony\Contracts\EventDispatcher\Event;
use Throwable;

final class HeaderCheckedFailureEvent extends Event
{
    /**
     * @var JWT
     */
    private $jwt;

    /**
     * @var int
     */
    private $index;

    /**
     * @var array
     */
    private $mandatoryHeaderParameters;

    /**
     * @var Throwable
     */
    private $throwable;

    public function __construct(JWT $jwt, int $index, array $mandatoryHeaderParameters, Throwable $throwable)
    {
        $this->jwt = $jwt;
        $this->index = $index;
        $this->mandatoryHeaderParameters = $mandatoryHeaderParameters;
        $this->throwable = $throwable;
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
