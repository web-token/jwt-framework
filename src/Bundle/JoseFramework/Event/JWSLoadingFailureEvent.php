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

use Jose\Component\Core\JWKSet;
use Symfony\Contracts\EventDispatcher\Event;
use Throwable;

final class JWSLoadingFailureEvent extends Event
{
    /**
     * @var JWKSet
     */
    private $JWKSet;

    /**
     * @var Throwable
     */
    private $throwable;

    /**
     * @var string
     */
    private $token;

    public function __construct(string $token, JWKSet $JWKSet, Throwable $throwable)
    {
        $this->JWKSet = $JWKSet;
        $this->throwable = $throwable;
        $this->token = $token;
    }

    public function getToken(): string
    {
        return $this->token;
    }

    public function getJWKSet(): JWKSet
    {
        return $this->JWKSet;
    }

    public function getThrowable(): Throwable
    {
        return $this->throwable;
    }
}
