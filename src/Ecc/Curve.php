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

namespace Jose\Component\Core\Util\Ecc;

/**
 * @internal
 */
class Curve
{
    /**
     * Elliptic curve over the field of integers modulo a prime.
     *
     * @var \GMP
     */
    private $a;

    /**
     * @var \GMP
     */
    private $b;

    /**
     * @var \GMP
     */
    private $prime;

    /**
     * Binary length of keys associated with these curve parameters.
     *
     * @var int
     */
    private $size;

    /**
     * @var Point
     */
    private $generator;

    public function __construct(int $size, \GMP $prime, \GMP $a, \GMP $b, Point $generator)
    {
        $this->size = $size;
        $this->prime = $prime;
        $this->a = $a;
        $this->b = $b;
        $this->generator = $generator;
    }

    public function getA(): \GMP
    {
        return $this->a;
    }

    public function getB(): \GMP
    {
        return $this->b;
    }

    public function getPrime(): \GMP
    {
        return $this->prime;
    }

    public function getSize(): int
    {
        return $this->size;
    }

    public function getPoint(\GMP $x, \GMP $y, ?\GMP $order = null): Point
    {
        if (!$this->contains($x, $y)) {
            throw new \RuntimeException('Curve '.$this->__toString().' does not contain point ('.Math::toString($x).', '.Math::toString($y).')');
        }
        $point = Point::create($x, $y, $order);
        if (!\is_null($order)) {
            $mul = $this->mul($point, $order);
            if (!$mul->isInfinity()) {
                throw new \RuntimeException('SELF * ORDER MUST EQUAL INFINITY. ('.(string) $mul.' found instead)');
            }
        }

        return $point;
    }

    public function getPublicKeyFrom(\GMP $x, \GMP $y): PublicKey
    {
        $zero = \gmp_init(0, 10);
        if (Math::cmp($x, $zero) < 0 || Math::cmp($this->generator->getOrder(), $x) <= 0 || Math::cmp($y, $zero) < 0 || Math::cmp($this->generator->getOrder(), $y) <= 0) {
            throw new \RuntimeException('Generator point has x and y out of range.');
        }
        $point = $this->getPoint($x, $y);

        return PublicKey::create($point);
    }

    public function contains(\GMP $x, \GMP $y): bool
    {
        $eq_zero = Math::equals(
            ModularArithmetic::sub(
                Math::pow($y, 2),
                Math::add(
                    Math::add(
                        Math::pow($x, 3),
                        Math::mul($this->getA(), $x)
                    ),
                    $this->getB()
                ),
                $this->getPrime()
            ),
            \gmp_init(0, 10)
        );

        return $eq_zero;
    }

    public function add(Point $one, Point $two): Point
    {
        if ($two->isInfinity()) {
            return clone $one;
        }

        if ($one->isInfinity()) {
            return clone $two;
        }

        if (Math::equals($two->getX(), $one->getX())) {
            if (Math::equals($two->getY(), $one->getY())) {
                return $this->getDouble($one);
            } else {
                return Point::infinity();
            }
        }

        $slope = ModularArithmetic::div(
            Math::sub($two->getY(), $one->getY()),
            Math::sub($two->getX(), $one->getX()),
            $this->getPrime()
        );

        $xR = ModularArithmetic::sub(
            Math::sub(Math::pow($slope, 2), $one->getX()),
            $two->getX(),
            $this->getPrime()
        );

        $yR = ModularArithmetic::sub(
            Math::mul($slope, Math::sub($one->getX(), $xR)),
            $one->getY(),
            $this->getPrime()
        );

        return $this->getPoint($xR, $yR, $one->getOrder());
    }

    public function mul(Point $one, \GMP $n): Point
    {
        if ($one->isInfinity()) {
            return Point::infinity();
        }

        /** @var \GMP $zero */
        $zero = \gmp_init(0, 10);
        if (Math::cmp($one->getOrder(), $zero) > 0) {
            $n = Math::mod($n, $one->getOrder());
        }

        if (Math::equals($n, $zero)) {
            return Point::infinity();
        }

        /** @var Point[] $r */
        $r = [
            Point::infinity(),
            clone $one,
        ];

        $k = $this->getSize();
        $n = \str_pad(Math::baseConvert(Math::toString($n), 10, 2), $k, '0', STR_PAD_LEFT);

        for ($i = 0; $i < $k; ++$i) {
            $j = $n[$i];
            Point::cswap($r[0], $r[1], $j ^ 1);
            $r[0] = $this->add($r[0], $r[1]);
            $r[1] = $this->getDouble($r[1]);
            Point::cswap($r[0], $r[1], $j ^ 1);
        }

        $this->validate($r[0]);

        return $r[0];
    }

    /**
     * @param Curve $other
     */
    public function cmp(self $other): int
    {
        $equal = Math::equals($this->getA(), $other->getA());
        $equal &= Math::equals($this->getB(), $other->getB());
        $equal &= Math::equals($this->getPrime(), $other->getPrime());

        return $equal ? 0 : 1;
    }

    /**
     * @param Curve $other
     */
    public function equals(self $other): bool
    {
        return 0 === $this->cmp($other);
    }

    public function __toString(): string
    {
        return 'curve('.Math::toString($this->getA()).', '.Math::toString($this->getB()).', '.Math::toString($this->getPrime()).')';
    }

    private function validate(Point $point)
    {
        if (!$point->isInfinity() && !$this->contains($point->getX(), $point->getY())) {
            throw new \RuntimeException('Invalid point');
        }
    }

    public function getDouble(Point $point): Point
    {
        if ($point->isInfinity()) {
            return Point::infinity();
        }

        $a = $this->getA();
        $threeX2 = Math::mul(\gmp_init(3, 10), Math::pow($point->getX(), 2));

        $tangent = ModularArithmetic::div(
            Math::add($threeX2, $a),
            Math::mul(\gmp_init(2, 10), $point->getY()),
            $this->getPrime()
        );

        $x3 = ModularArithmetic::sub(
            Math::pow($tangent, 2),
            Math::mul(\gmp_init(2, 10), $point->getX()),
            $this->getPrime()
        );

        $y3 = ModularArithmetic::sub(
            Math::mul($tangent, Math::sub($point->getX(), $x3)),
            $point->getY(),
            $this->getPrime()
        );

        return $this->getPoint($x3, $y3, $point->getOrder());
    }

    public function createPrivateKey(): PrivateKey
    {
        return PrivateKey::create($this->generate());
    }

    public function createPublicKey(PrivateKey $privateKey): PublicKey
    {
        $point = $this->mul($this->generator, $privateKey->getSecret());

        return PublicKey::create($point);
    }

    private function generate(): \GMP
    {
        $max = $this->generator->getOrder();
        $numBits = $this->bnNumBits($max);
        $numBytes = (int) \ceil($numBits / 8);
        // Generate an integer of size >= $numBits
        $bytes = \random_bytes($numBytes);
        $value = Math::stringToInt($bytes);
        $mask = \gmp_sub(\gmp_pow(2, $numBits), 1);
        $integer = \gmp_and($value, $mask);

        return $integer;
    }

    /**
     * Returns the number of bits used to store this number. Non-significant upper bits are not counted.
     *
     * @see https://www.openssl.org/docs/crypto/BN_num_bytes.html
     */
    private function bnNumBits(\GMP $x): int
    {
        $zero = \gmp_init(0, 10);
        if (Math::equals($x, $zero)) {
            return 0;
        }
        $log2 = 0;
        while (false === Math::equals($x, $zero)) {
            $x = Math::rightShift($x, 1);
            ++$log2;
        }

        return $log2;
    }

    public function getGenerator(): Point
    {
        return $this->generator;
    }
}
