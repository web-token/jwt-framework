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

namespace Jose\Easy;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\Signature\Algorithm;
use Jose\Component\Signature\JWSBuilder as JoseBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;

class JWSBuilder extends AbstractBuilder
{
    public function __construct()
    {
        parent::__construct();
        $this->algorithms = [
            new Algorithm\HS256(),
            new Algorithm\HS384(),
            new Algorithm\HS512(),
            new Algorithm\RS256(),
            new Algorithm\RS384(),
            new Algorithm\RS512(),
            new Algorithm\PS256(),
            new Algorithm\PS384(),
            new Algorithm\PS512(),
            new Algorithm\ES256(),
            new Algorithm\ES384(),
            new Algorithm\ES512(),
            new Algorithm\EdDSA(),
        ];
    }

    public function sign(JWK $jwk): string
    {
        $builder = new JoseBuilder(new AlgorithmManager($this->algorithms));
        $jws = $builder
            ->create()
            ->withPayload(JsonConverter::encode($this->jwt->claims->all()))
            ->addSignature($jwk, $this->jwt->header->all())
            ->build()
        ;

        return (new CompactSerializer())->serialize($jws);
    }
}
