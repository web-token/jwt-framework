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

final class NestedTokenIssuedEvent extends Event
{
    /**
     * @var string
     */
    private $nestedToken;

    public function __construct(string $nestedToken)
    {
        $this->nestedToken = $nestedToken;
    }

    public function getNestedToken(): string
    {
        return $this->nestedToken;
    }
}
