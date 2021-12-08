<?php

declare(strict_types=1);

namespace Jose\Easy;

use InvalidArgumentException;
use function is_string;
use Jose\Component\Core\Algorithm as JoseAlgorithm;

abstract class AbstractBuilder
{
    protected JWT $jwt;

    /**
     * @var JoseAlgorithm[]
     */
    protected array $algorithms = [];

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

    public function alg(JoseAlgorithm|string $alg): self
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
                throw new InvalidArgumentException(
                    'Invalid parameter "alg". Shall be a string or an algorithm instance.'
                );
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

    public function claim(string $key, $value, bool $inHeader = false): self
    {
        $clone = clone $this;
        $clone->jwt->claims->set($key, $value);
        if ($inHeader) {
            $clone->jwt->header->set($key, $value);
        }

        return $clone;
    }

    public function header(string $key, $value): self
    {
        $clone = clone $this;
        $clone->jwt->header->set($key, $value);

        return $clone;
    }

    abstract protected function getAlgorithmMap(): array;
}
