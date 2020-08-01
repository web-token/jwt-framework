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

namespace Jose\Component\Core\Util;

use Brick\Math\BigInteger as BrickBigInteger;
use Brick\Math\RoundingMode;
use function chr;
use function function_exists;
use InvalidArgumentException;
use RuntimeException;

/**
 * @internal
 */
class BigInteger
{
    /**
     * Holds the BigInteger's value.
     *
     * @var BrickBigInteger
     */
    private $value;

    private function __construct(BrickBigInteger $value)
    {
        $this->value = $value;
    }

    /**
     * @return BigInteger
     */
    public static function createFromBinaryString(string $value): self
    {
        $data = current(unpack('H*', $value));

        return new self(BrickBigInteger::fromBase($data, 16));
    }

    /**
     * @return BigInteger
     */
    public static function createFromDecimal(int $value): self
    {
        return new self(BrickBigInteger::of($value));
    }

    /**
     * @return BigInteger
     */
    public static function createFromBigInteger(BrickBigInteger $value): self
    {
        return new self($value);
    }

    /**
     * Converts a BigInteger to a binary string.
     */
    public function toBytes(): string
    {
        if ($this->value->isEqualTo(BrickBigInteger::zero())) {
            return '';
        }

        $temp = $this->value->toBase(16);
        $temp = 0 !== (mb_strlen($temp, '8bit') & 1) ? '0'.$temp : $temp;
        $temp = hex2bin($temp);

        return ltrim($temp, chr(0));
    }

    /**
     * Adds two BigIntegers.
     *
     *  @param BigInteger $y
     *
     *  @return BigInteger
     */
    public function add(self $y): self
    {
        $value = $this->value->plus($y->value);

        return new self($value);
    }

    /**
     * Subtracts two BigIntegers.
     *
     *  @param BigInteger $y
     *
     *  @return BigInteger
     */
    public function subtract(self $y): self
    {
        $value = $this->value->minus($y->value);

        return new self($value);
    }

    /**
     * Multiplies two BigIntegers.
     *
     * @param BigInteger $x
     *
     *  @return BigInteger
     */
    public function multiply(self $x): self
    {
        $value = $this->value->multipliedBy($x->value);

        return new self($value);
    }

    /**
     * Divides two BigIntegers.
     *
     * @param BigInteger $x
     *
     *  @return BigInteger
     */
    public function divide(self $x): self
    {
        $value = $this->value->dividedBy($x->value);

        return new self($value);
    }

    /**
     * Performs modular exponentiation.
     *
     * @param BigInteger $e
     * @param BigInteger $n
     *
     * @return BigInteger
     */
    public function modPow(self $e, self $n): self
    {
        $value = $this->value->powerMod($e->value, $n->value);

        return new self($value);
    }

    /**
     * Performs modular exponentiation.
     *
     * @param BigInteger $d
     *
     * @return BigInteger
     */
    public function mod(self $d): self
    {
        $value = $this->value->mod($d->value);

        return new self($value);
    }

    public function modInverse(BigInteger $m): BigInteger
    {
        $x = BrickBigInteger::zero();
        $y = BrickBigInteger::zero();
        $g = $this->gcdExtended($this->value, $m->value, $x, $y);
        if (!$g->isEqualTo(BrickBigInteger::one())) {
            throw new InvalidArgumentException('Unable to compute the modInverse for the given modulus');
        }

        return new self($x->mod($m->value)->plus($m->value)->mod($m->value));
    }

    /**
     * Compares two numbers.
     *
     * @param BigInteger $y
     */
    public function compare(self $y): int
    {
        return $this->value->compareTo($y->value);
    }

    /**
     * @param BigInteger $y
     */
    public function equals(self $y): bool
    {
        return $this->value->isEqualTo($y->value);
    }

    /**
     * @param BigInteger $y
     *
     * @return BigInteger
     */
    public static function random(self $y): self
    {
        if (!function_exists('gmp_random_range')) {
            throw new RuntimeException('The extension "GMP" is required');
        }
        $zero = gmp_init(0, 10);
        $limit = gmp_init($y->value->toBase(10), 10);
        $rnd = gmp_strval(gmp_random_range($zero, $limit), 10);

        return new self(BrickBigInteger::fromBase($rnd, 10));
    }

    /**
     * @param BigInteger $y
     *
     * @return BigInteger
     */
    public function gcd(self $y): self
    {
        return new self($this->value->gcd($y->value));
    }

    /**
     * @param BigInteger $y
     */
    public function lowerThan(self $y): bool
    {
        return $this->value->isLessThan($y->value);
    }

    public function isEven(): bool
    {
        return $this->value->isEven();
    }

    public function get(): BrickBigInteger
    {
        return $this->value;
    }

    private function gcdExtended(BrickBigInteger $a, BrickBigInteger $b, BrickBigInteger &$x, BrickBigInteger &$y): BrickBigInteger
    {
        if ($a->isEqualTo(BrickBigInteger::zero())) {
            $x = BrickBigInteger::zero();
            $y = BrickBigInteger::one();

            return $b;
        }

        $x1 = BrickBigInteger::zero();
        $y1 = BrickBigInteger::zero();
        $gcd = $this->gcdExtended($b->mod($a), $a, $x1, $y1);

        $x = $y1->minus($b->dividedBy($a, RoundingMode::FLOOR)->multipliedBy($x1));
        $y = $x1;

        return $gcd;
    }
}
