<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2019 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Bundle\JoseFramework\Controller;

use Jose\Component\Core\Converter\JsonConverter;
use Jose\Component\Core\JWKSet;

class JWKSetControllerFactory
{
    private $jsonConverter;

    public function __construct(JsonConverter $jsonConverter)
    {
        $this->jsonConverter = $jsonConverter;
    }

    public function create(JWKSet $jwkset): JWKSetController
    {
        return new JWKSetController($this->jsonConverter->encode($jwkset));
    }
}
