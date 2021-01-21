<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Bundle\JoseFramework\Controller;

use Jose\Component\Core\JWKSet;
use Jose\Component\Core\Util\JsonConverter;

class JWKSetControllerFactory
{
    public function create(JWKSet $jwkset): JWKSetController
    {
        return new JWKSetController(JsonConverter::encode($jwkset));
    }
}
