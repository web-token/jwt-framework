<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Performance\JWS;

use Jose\Component\Checker\ExpirationTimeChecker;
use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Checker\IssuedAtChecker;
use Jose\Component\Checker\NotBeforeChecker;
use Jose\Component\Core\Converter\JsonConverterInterface;
use Jose\Component\Core\Converter\JsonConverter;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm;
use Jose\Component\Signature\Algorithm\SignatureAlgorithmInterface;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWSLoader;
use Jose\Component\Signature\JWSTokenHeaderChecker;
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
    /**
     * @var string
     */
    private $payload = "It\xe2\x80\x99s a dangerous business, Frodo, going out your door. You step onto the road, and if you don't keep your feet, there\xe2\x80\x99s no knowing where you might be swept off to.";

    /**
     * @param JWAManager
     */
    private $signatureAlgorithmsManager;

    /**
     * @var HeaderCheckerManager
     */
    private $headerCherckerManager;

    /**
     * @var JsonConverterInterface
     */
    private $jsonConverter;

    /**
     * @var JWSSerializerManager
     */
    private $serializerManager;

    public function init()
    {
        $this->jsonConverter = new JsonConverter();
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
        $this->headerCherckerManager = HeaderCheckerManager::create([
            new ExpirationTimeChecker(),
            new IssuedAtChecker(),
            new NotBeforeChecker(),
        ], [
            new JWSTokenHeaderChecker(),
        ]);
        $this->serializerManager = JWSSerializerManager::create([
            new CompactSerializer($this->jsonConverter),
            new JSONFlattenedSerializer($this->jsonConverter),
            new JSONGeneralSerializer($this->jsonConverter),
        ]);
    }

    /**
     * @param array $params
     *
     * @Subject()
     * @ParamProviders({"dataSignature"})
     */
    public function sign($params)
    {
        $jwsBuilder = new JWSBuilder($this->jsonConverter, $this->signatureAlgorithmsManager);
        $jwsBuilder
            ->withPayload($this->payload)
            ->addSignature($this->getPrivateKey(), ['alg' => $params['algorithm']])
            ->build();
    }

    /**
     * @param array $params
     *
     * @Subject()
     * @ParamProviders({"dataVerification"})
     */
    public function verify($params)
    {
        $jwsLoader = new JWSLoader($this->signatureAlgorithmsManager, $this->headerCherckerManager, $this->serializerManager);
        $jws = $jwsLoader->load($params['input']);
        $jwsLoader->verifyWithKey($jws, $this->getPublicKey());
    }

    /**
     * @return AlgorithmManager
     */
    protected function getSignatureAlgorithmsManager(): AlgorithmManager
    {
        return $this->signatureAlgorithmsManager;
    }

    /**
     * @return SignatureAlgorithmInterface
     */
    abstract protected function getAlgorithm(): SignatureAlgorithmInterface;

    /**
     * @return string
     */
    abstract protected function getInput(): string;

    /**
     * @return JWK
     */
    abstract protected function getPrivateKey(): JWK;

    /**
     * @return JWK
     */
    abstract protected function getPublicKey(): JWK;
}
