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

class JWSBuilder
{
    private $jwt;

    /**
     * @var CompactSerializer
     */
    private $serializer;

    /**
     * @var AlgorithmManager
     */
    private $algorithms;

    /**
     * @var null|Algorithm\SignatureAlgorithm
     */
    private $signatureAlgorithm;

    public function __construct()
    {
        $this->jwt = new JWT();
        $this->serializer = new CompactSerializer();
        $this->algorithms = new AlgorithmManager([
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
            new Algorithm\None(),
        ]);
    }

    public function payload(array $payload): self
    {
        $clone = clone $this;
        $clone->jwt->payload->replace($payload);

        return $clone;
    }

    public function iss(string $iss, bool $inHeader = false): self
    {
        return $this->claim('iss', $iss, $inHeader);
    }

    public function sub(string $sub, bool $inHeader = false): self
    {
        return $this->claim('sub', $sub, $inHeader);
    }

    public function aud(string $aud, bool $inHeader = false): self
    {
        $audience = $this->jwt->payload->get('aud', []);
        $audience[] = $aud;

        return $this->claim('aud', $audience, $inHeader);
    }

    public function jti(string $jti, bool $inHeader = false): self
    {
        return $this->claim('jti', $jti, $inHeader);
    }

    public function exp(int $exp, bool $inHeader = false): self
    {
        return $this->claim('exp', $exp, $inHeader);
    }

    public function iat(int $iat, bool $inHeader = false): self
    {
        return $this->claim('iat', $iat, $inHeader);
    }

    public function nbf(int $nbf, bool $inHeader = false): self
    {
        return $this->claim('nbf', $nbf, $inHeader);
    }

    /**
     * @param Algorithm\SignatureAlgorithm|string $alg
     */
    public function alg($alg): self
    {
        if ($alg instanceof \Jose\Component\Core\Algorithm) {
            $clone = clone $this;
            $clone->signatureAlgorithm = $alg;
            $clone->jwt->header->set('alg', $alg->name());

            return $clone;
        }
        if (!\is_string($alg)) {
            throw new \InvalidArgumentException('Invalid algorithm');
        }
        $clone = clone $this;
        $clone->signatureAlgorithm = null;

        return $this->header('alg', $alg);
    }

    public function cty(string $cty): self
    {
        return $this->header('cty', $cty);
    }

    public function typ(string $typ): self
    {
        return $this->header('typ', $typ);
    }

    /**
     * @param mixed $value
     */
    public function claim(string $key, $value, bool $inHeader = false): self
    {
        $clone = clone $this;
        $clone->jwt->payload->set($key, $value);
        if ($inHeader) {
            $clone->jwt->header->set($key, $value);
        }

        return $clone;
    }

    /**
     * @param mixed $value
     */
    public function header(string $key, $value): self
    {
        $clone = clone $this;
        $clone->jwt->header->set($key, $value);

        return $clone;
    }

    public function sign(JWK $jwk): string
    {
        $algorithms = $this->algorithms;
        if (null !== $this->signatureAlgorithm) {
            $algorithms = new AlgorithmManager([$this->signatureAlgorithm]);
        }
        $builder = new JoseBuilder($algorithms);
        $jws = $builder
            ->create()
            ->withPayload(JsonConverter::encode($this->jwt->payload->all()))
            ->addSignature($jwk, $this->jwt->header->all())
            ->build()
        ;

        return $this->serializer->serialize($jws);
    }
}
