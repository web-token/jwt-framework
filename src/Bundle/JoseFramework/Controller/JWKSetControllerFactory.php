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

use Jose\Component\Core\Converter\JsonConverter;
use Jose\Component\Core\JWKSet;

class JWKSetControllerFactory
{
    /**
     * @var JsonConverter|\Jose\Component\Core\Util\JsonConverter
     */
    private $jsonConverter;

    public function __construct(?JsonConverter $jsonConverter = null)
    {
        $this->jsonConverter = $jsonConverter ?? new \Jose\Component\Core\Util\JsonConverter();
    }

    public function create(JWKSet $jwkset, int $maxAge): JWKSetController
    {
        return new JWKSetController($this->jsonConverter->encode($jwkset), $maxAge);
    }
}
