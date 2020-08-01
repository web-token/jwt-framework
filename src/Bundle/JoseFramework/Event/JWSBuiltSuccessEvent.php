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

use Jose\Component\Signature\JWS;
use Symfony\Contracts\EventDispatcher\Event;

final class JWSBuiltSuccessEvent extends Event
{
    /**
     * @var JWS
     */
    private $jws;

    public function __construct(JWS $jws)
    {
        $this->jws = $jws;
    }

    public function getJws(): JWS
    {
        return $this->jws;
    }
}
