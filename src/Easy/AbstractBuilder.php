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

use InvalidArgumentException;
use function is_string;
use Jose\Component\Core\Algorithm as JoseAlgorithm;
use Jose\Component\Signature\Algorithm;

abstract class AbstractBuilder
{
    /**
     * @var JWT
     */
    protected $jwt;

    /**
     * @var JoseAlgorithm[]
     */
    protected $algorithms = [];

    public function __construct()
    {
        $this->jwt = new JWT();
        $this->algorithms = (new AlgorithmProvider($this->getAlgorithmMap()))
            ->getAvailableAlgorithms()
        ;
    }

    public function payload(array $payload): self
    {
        $clone = clone $this;
        $clone->jwt->claims->replace($payload);

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
        $audience = $this->jwt->claims->has('aud') ? $this->jwt->claims->get('aud') : [];
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

    public function iat(?int $iat = null, bool $inHeader = false): self
    {
        $iat = $iat ?? time();

        return $this->claim('iat', $iat, $inHeader);
    }

    public function nbf(?int $nbf = null, bool $inHeader = false): self
    {
        $nbf = $nbf ?? time();

        return $this->claim('nbf', $nbf, $inHeader);
    }

    /**
     * @param Algorithm\SignatureAlgorithm|string $alg
     *
     * @throws InvalidArgumentException if the algorithm is not a string or an instance of Jose\Component\Core\Algorithm
     */
    public function alg($alg): self
    {
        $clone = clone $this;
        switch (true) {
            case $alg instanceof JoseAlgorithm:
                $clone->algorithms[] = $alg;
                $clone->jwt->header->set('alg', $alg->name());

                break;
            case is_string($alg):
                $clone->jwt->header->set('alg', $alg);

                break;
            default:
                throw new InvalidArgumentException('Invalid parameter "alg". Shall be a string or an algorithm instance.');
        }

        return $clone;
    }

    public function cty(string $cty): self
    {
        return $this->header('cty', $cty);
    }

    public function typ(string $typ): self
    {
        return $this->header('typ', $typ);
    }

    public function crit(array $crit): self
    {
        return $this->header('crit', $crit);
    }

    /**
     * @param mixed $value
     */
    public function claim(string $key, $value, bool $inHeader = false): self
    {
        $clone = clone $this;
        $clone->jwt->claims->set($key, $value);
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

    abstract protected function getAlgorithmMap(): array;
}
