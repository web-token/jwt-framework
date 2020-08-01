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

use Jose\Component\Encryption\JWE;
use Symfony\Contracts\EventDispatcher\Event;

final class JWEBuiltSuccessEvent extends Event
{
    /**
     * @var JWE
     */
    private $jwe;

    public function __construct(JWE $jwe)
    {
        $this->jwe = $jwe;
    }

    public function getJwe(): JWE
    {
        return $this->jwe;
    }
}
