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

namespace Jose\Easy;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\Signature\Algorithm;
use Jose\Component\Signature\JWSBuilder as JoseBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;

class JWSBuilder extends AbstractBuilder
{
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

    protected function getAlgorithmMap(): array
    {
        return [
            Algorithm\HS256::class,
            Algorithm\HS384::class,
            Algorithm\HS512::class,
            Algorithm\RS256::class,
            Algorithm\RS384::class,
            Algorithm\RS512::class,
            Algorithm\PS256::class,
            Algorithm\PS384::class,
            Algorithm\PS512::class,
            Algorithm\ES256::class,
            Algorithm\ES384::class,
            Algorithm\ES512::class,
            Algorithm\EdDSA::class,
        ];
    }
}
