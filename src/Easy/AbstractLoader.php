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

use function in_array;
use InvalidArgumentException;
use function is_array;
use function is_callable;
use function is_int;
use function is_string;
use Jose\Component\Checker;
use Jose\Component\Core\Algorithm;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;

abstract class AbstractLoader
{
    /**
     * @var string
     */
    protected $token;

    /**
     * @var JWKSet
     */
    protected $jwkset;

    /**
     * @var Checker\HeaderChecker[]
     */
    protected $headerCheckers = [];

    /**
     * @var Checker\ClaimChecker[]
     */
    protected $claimCheckers = [];

    /**
     * @var string[]
     */
    protected $allowedAlgorithms = [];

    /**
     * @var Algorithm[]
     */
    protected $algorithms = [];

    /**
     * @var string[]
     */
    protected $mandatoryClaims = [];

    protected function __construct(string $token)
    {
        $this->token = $token;
        $this->jwkset = new JWKSet([]);
        $this->claimCheckers = [];

        $this->algorithms = (new AlgorithmProvider($this->getAlgorithmMap()))
            ->getAvailableAlgorithms()
        ;
    }

    /**
     * @param string[] $mandatoryClaims
     */
    public function mandatory(array $mandatoryClaims): self
    {
        $clone = clone $this;
        $clone->mandatoryClaims = $mandatoryClaims;

        return $clone;
    }

    public function aud(string $aud, bool $inHeader = false): self
    {
        return $this->claim('aud', new Checker\AudienceChecker($aud, true), $inHeader);
    }

    public function iss(string $iss, bool $inHeader = false): self
    {
        return $this->claim('iss', new Checker\IssuerChecker([$iss], true), $inHeader);
    }

    public function jti(string $jti, bool $inHeader = false): self
    {
        return $this->claim('jti', $jti, $inHeader);
    }

    public function sub(string $sub, bool $inHeader = false): self
    {
        return $this->claim('sub', $sub, $inHeader);
    }

    /**
     * @param null|array|callable|Checker\ClaimChecker $checker
     */
    public function claim(string $key, $checker, bool $inHeader = false): self
    {
        $clone = clone $this;
        if (false === $checker) {
            unset($clone->claimCheckers[$key]);

            return $clone;
        }

        switch (true) {
            case $checker instanceof Checker\ClaimChecker:
                break;

            case is_callable($checker):
                $checker = new CallableChecker($key, $checker);

                break;

            case is_array($checker):
                $checker = new CallableChecker($key, static function ($value) use ($checker): bool {return in_array($value, $checker, true); });

                break;

            default:
                $checker = new CallableChecker($key, static function ($value) use ($checker): bool {return $value === $checker; });
        }

        $clone->claimCheckers[$key] = $checker;
        if ($inHeader) {
            return $clone->header($key, $checker);
        }

        return $clone;
    }

    /**
     * @param false|int $leeway
     *
     * @throws InvalidArgumentException if the leeway is negative, not an integer or not false
     */
    public function exp($leeway = 0, bool $inHeader = false): self
    {
        if (false === $leeway) {
            $clone = clone $this;
            unset($clone->claimCheckers['exp']);

            return $clone;
        }
        if (!is_int($leeway) or $leeway < 0) {
            throw new InvalidArgumentException('First parameter for "exp" claim is invalid. Set false to disable or a positive integer.');
        }

        return $this->claim('exp', new Checker\ExpirationTimeChecker($leeway), $inHeader);
    }

    /**
     * @param false|int $leeway
     *
     * @throws InvalidArgumentException if the leeway is negative, not an integer or not false
     */
    public function nbf($leeway = 0, bool $inHeader = false): self
    {
        if (false === $leeway) {
            $clone = clone $this;
            unset($clone->claimCheckers['nbf']);

            return $clone;
        }
        if (!is_int($leeway) or $leeway < 0) {
            throw new InvalidArgumentException('First parameter for "nbf" claim is invalid. Set false to disable or a positive integer.');
        }

        return $this->claim('nbf', new Checker\NotBeforeChecker($leeway, true), $inHeader);
    }

    /**
     * @param false|int $leeway
     *
     * @throws InvalidArgumentException if the leeway is negative, not an integer or not false
     */
    public function iat($leeway = 0, bool $inHeader = false): self
    {
        if (false === $leeway) {
            $clone = clone $this;
            unset($clone->claimCheckers['iat']);

            return $clone;
        }
        if (!is_int($leeway) or $leeway < 0) {
            throw new InvalidArgumentException('First parameter for "iat" claim is invalid. Set false to disable or a positive integer.');
        }

        return $this->claim('iat', new Checker\IssuedAtChecker($leeway, true), $inHeader);
    }

    /**
     * @param Algorithm|string $alg
     *
     * @throws InvalidArgumentException if the algorithm is not a string or an instance of Jose\Component\Core\Algorithm
     */
    public function alg($alg): self
    {
        $clone = clone $this;

        switch (true) {
            case is_string($alg):
                $clone->allowedAlgorithms[] = $alg;

                return $clone;

            case $alg instanceof Algorithm:
                $clone->algorithms[$alg->name()] = $alg;
                $clone->allowedAlgorithms[] = $alg->name();

                return $clone;

            default:
                throw new InvalidArgumentException('Invalid parameter "alg". Shall be a string or an algorithm instance.');
        }
    }

    /**
     * @param Algorithm[]|string[] $algs
     */
    public function algs($algs): self
    {
        $clone = clone $this;
        foreach ($algs as $alg) {
            $clone = $clone->alg($alg);
        }

        return $clone;
    }

    /**
     * @param array|callable|Checker\HeaderChecker|false|mixed $checker
     */
    public function header(string $key, $checker): self
    {
        $clone = clone $this;
        if (false === $checker) {
            unset($clone->headerCheckers[$key]);

            return $clone;
        }

        switch (true) {
            case $checker instanceof Checker\HeaderChecker:
                break;

            case is_callable($checker):
                $checker = new CallableChecker($key, $checker);

                break;

            case is_array($checker):
                $checker = new CallableChecker($key, static function ($value) use ($checker): bool {return in_array($value, $checker, true); });

                break;

            default:
                $checker = new CallableChecker($key, static function ($value) use ($checker): bool {return $value === $checker; });
        }

        $clone->headerCheckers[$key] = $checker;

        return $clone;
    }

    public function key(JWK $jwk): self
    {
        $clone = clone $this;
        $jwkset = $this->jwkset->with($jwk);
        $clone->jwkset = $jwkset;

        return $clone;
    }

    public function keyset(JWKSet $jwkset): self
    {
        $clone = clone $this;
        $clone->jwkset = $jwkset;

        return $clone;
    }

    abstract protected function getAlgorithmMap(): array;
}
