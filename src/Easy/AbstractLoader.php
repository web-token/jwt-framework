<?php

declare(strict_types=1);

namespace Jose\Easy;

use function in_array;
use InvalidArgumentException;
use function is_array;
use function is_callable;
use function is_int;
use function is_string;
use Jose\Component\Checker;
use Jose\Component\Checker\AudienceChecker;
use Jose\Component\Checker\ClaimChecker;
use Jose\Component\Checker\ExpirationTimeChecker;
use Jose\Component\Checker\HeaderChecker;
use Jose\Component\Checker\IssuedAtChecker;
use Jose\Component\Checker\IssuerChecker;
use Jose\Component\Checker\NotBeforeChecker;
use Jose\Component\Core\Algorithm;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;

abstract class AbstractLoader
{
    protected JWKSet $jwkset;

    /**
     * @var Checker\HeaderChecker[]
     */
    protected array $headerCheckers = [];

    /**
     * @var Checker\ClaimChecker[]
     */
    protected array $claimCheckers = [];

    /**
     * @var string[]
     */
    protected array $allowedAlgorithms = [];

    /**
     * @var Algorithm[]
     */
    protected array $algorithms = [];

    /**
     * @var string[]
     */
    protected array $mandatoryClaims = [];

    protected function __construct(
        protected string $token
    ) {
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
        return $this->claim('aud', new AudienceChecker($aud, true), $inHeader);
    }

    public function iss(string $iss, bool $inHeader = false): self
    {
        return $this->claim('iss', new IssuerChecker([$iss], true), $inHeader);
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
     * @param array|callable|Checker\ClaimChecker|mixed|null $checker
     */
    public function claim(string $key, $checker, bool $inHeader = false): self
    {
        $clone = clone $this;
        if ($checker === false) {
            unset($clone->claimCheckers[$key]);

            return $clone;
        }

        switch (true) {
            case $checker instanceof ClaimChecker:
                break;

            case is_callable($checker):
                $checker = new CallableChecker($key, $checker);

                break;

            case is_array($checker):
                $checker = new CallableChecker($key, static function ($value) use ($checker): bool {
                    return in_array($value, $checker, true);
                });

                break;

            default:
                $checker = new CallableChecker($key, static function ($value) use ($checker): bool {
                    return $value === $checker;
                });
        }

        $clone->claimCheckers[$key] = $checker;
        if ($inHeader) {
            return $clone->header($key, $checker);
        }

        return $clone;
    }

    public function exp(int|false $leeway = 0, bool $inHeader = false): self
    {
        if ($leeway === false) {
            $clone = clone $this;
            unset($clone->claimCheckers['exp']);

            return $clone;
        }
        if (! is_int($leeway) || $leeway < 0) {
            throw new InvalidArgumentException(
                'First parameter for "exp" claim is invalid. Set false to disable or a positive integer.'
            );
        }

        return $this->claim('exp', new ExpirationTimeChecker($leeway), $inHeader);
    }

    public function nbf(int|false $leeway = 0, bool $inHeader = false): self
    {
        if ($leeway === false) {
            $clone = clone $this;
            unset($clone->claimCheckers['nbf']);

            return $clone;
        }
        if (! is_int($leeway) || $leeway < 0) {
            throw new InvalidArgumentException(
                'First parameter for "nbf" claim is invalid. Set false to disable or a positive integer.'
            );
        }

        return $this->claim('nbf', new NotBeforeChecker($leeway, true), $inHeader);
    }

    public function iat(int|false $leeway = 0, bool $inHeader = false): self
    {
        if ($leeway === false) {
            $clone = clone $this;
            unset($clone->claimCheckers['iat']);

            return $clone;
        }
        if (! is_int($leeway) || $leeway < 0) {
            throw new InvalidArgumentException(
                'First parameter for "iat" claim is invalid. Set false to disable or a positive integer.'
            );
        }

        return $this->claim('iat', new IssuedAtChecker($leeway, true), $inHeader);
    }

    public function alg(Algorithm|string $alg): self
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
                throw new InvalidArgumentException(
                    'Invalid parameter "alg". Shall be a string or an algorithm instance.'
                );
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
        if ($checker === false) {
            unset($clone->headerCheckers[$key]);

            return $clone;
        }

        switch (true) {
            case $checker instanceof HeaderChecker:
                break;

            case is_callable($checker):
                $checker = new CallableChecker($key, $checker);

                break;

            case is_array($checker):
                $checker = new CallableChecker($key, static function ($value) use ($checker): bool {
                    return in_array($value, $checker, true);
                });

                break;

            default:
                $checker = new CallableChecker($key, static function ($value) use ($checker): bool {
                    return $value === $checker;
                });
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
