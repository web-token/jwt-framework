<?php

declare(strict_types=1);

namespace Jose\Easy;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\Signature\Algorithm\EdDSA;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\ES384;
use Jose\Component\Signature\Algorithm\ES512;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\Algorithm\HS384;
use Jose\Component\Signature\Algorithm\HS512;
use Jose\Component\Signature\Algorithm\PS256;
use Jose\Component\Signature\Algorithm\PS384;
use Jose\Component\Signature\Algorithm\PS512;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\Algorithm\RS384;
use Jose\Component\Signature\Algorithm\RS512;
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
            HS256::class,
            HS384::class,
            HS512::class,
            RS256::class,
            RS384::class,
            RS512::class,
            PS256::class,
            PS384::class,
            PS512::class,
            ES256::class,
            ES384::class,
            ES512::class,
            EdDSA::class,
        ];
    }
}
