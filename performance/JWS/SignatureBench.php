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

namespace Jose\Performance\JWS;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\Converter\StandardConverter;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm;
use Jose\Component\Signature\Algorithm\SignatureAlgorithm;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JSONFlattenedSerializer;
use Jose\Component\Signature\Serializer\JSONGeneralSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManager;

/**
 * @BeforeMethods({"init"})
 * @Revs(100)
 */
abstract class SignatureBench
{
    private $payload = "It\xe2\x80\x99s a dangerous business, Frodo, going out your door. You step onto the road, and if you don't keep your feet, there\xe2\x80\x99s no knowing where you might be swept off to.";
    private $signatureAlgorithmsManager;
    private $jsonConverter;
    private $serializerManager;

    public function init()
    {
        $this->jsonConverter = new StandardConverter();
        $this->signatureAlgorithmsManager = AlgorithmManager::create([
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
            new Algorithm\None(),
            new Algorithm\EdDSA(),
        ]);
        $this->serializerManager = JWSSerializerManager::create([
            new CompactSerializer($this->jsonConverter),
            new JSONFlattenedSerializer($this->jsonConverter),
            new JSONGeneralSerializer($this->jsonConverter),
        ]);
    }

    /**
     * @Subject
     * @ParamProviders({"dataSignature"})
     */
    public function sign(array $params)
    {
        $jwsBuilder = new JWSBuilder($this->jsonConverter, $this->signatureAlgorithmsManager);
        $jwsBuilder
            ->withPayload($this->payload)
            ->addSignature($this->getPrivateKey(), ['alg' => $params['algorithm']])
            ->build();
    }

    /**
     * @Subject
     * @ParamProviders({"dataVerification"})
     */
    public function verify(array $params)
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
