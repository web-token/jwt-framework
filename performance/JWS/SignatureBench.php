<?php

declare(strict_types=1);

namespace Jose\Performance\JWS;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\EdDSA;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\ES384;
use Jose\Component\Signature\Algorithm\ES512;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\Algorithm\HS384;
use Jose\Component\Signature\Algorithm\HS512;
use Jose\Component\Signature\Algorithm\None;
use Jose\Component\Signature\Algorithm\PS256;
use Jose\Component\Signature\Algorithm\PS384;
use Jose\Component\Signature\Algorithm\PS512;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\Algorithm\RS384;
use Jose\Component\Signature\Algorithm\RS512;
use Jose\Component\Signature\Algorithm\SignatureAlgorithm;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JSONFlattenedSerializer;
use Jose\Component\Signature\Serializer\JSONGeneralSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use PhpBench\Benchmark\Metadata\Annotations\Revs;

/**
 * @BeforeMethods({"init"})
 * @Revs(100)
 */
abstract class SignatureBench
{
    private string $payload = "It\xe2\x80\x99s a dangerous business, Frodo, going out your door. You step onto the road, and if you don't keep your feet, there\xe2\x80\x99s no knowing where you might be swept off to.";

    private AlgorithmManager $signatureAlgorithmsManager;

    private JWSSerializerManager $serializerManager;

    public function init(): void
    {
        $this->signatureAlgorithmsManager = new AlgorithmManager([
            new HS256(),
            new HS384(),
            new HS512(),
            new RS256(),
            new RS384(),
            new RS512(),
            new PS256(),
            new PS384(),
            new PS512(),
            new ES256(),
            new ES384(),
            new ES512(),
            new None(),
            new EdDSA(),
        ]);
        $this->serializerManager = new JWSSerializerManager([
            new CompactSerializer(),
            new JSONFlattenedSerializer(),
            new JSONGeneralSerializer(),
        ]);
    }

    /**
     * @Subject
     * @ParamProviders({"dataSignature"})
     */
    public function sign(array $params): void
    {
        $jwsBuilder = new JWSBuilder($this->signatureAlgorithmsManager);
        $jwsBuilder
            ->withPayload($this->payload)
            ->addSignature($this->getPrivateKey(), [
                'alg' => $params['algorithm'],
            ])
            ->build()
        ;
    }

    /**
     * @Subject
     * @ParamProviders({"dataVerification"})
     */
    public function verify(array $params): void
    {
        $jwsLoader = new JWSVerifier($this->signatureAlgorithmsManager);
        $jws = $this->serializerManager->unserialize($params['input']);
        $jwsLoader->verifyWithKey($jws, $this->getPublicKey(), 0);
    }

    protected function getSignatureAlgorithmsManager(): AlgorithmManager
    {
        return $this->signatureAlgorithmsManager;
    }

    abstract protected function getAlgorithm(): SignatureAlgorithm;

    abstract protected function getInput(): string;

    abstract protected function getPrivateKey(): JWK;

    abstract protected function getPublicKey(): JWK;
}
