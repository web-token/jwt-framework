<?php

declare(strict_types=1);

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
