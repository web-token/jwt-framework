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

namespace Jose\Component\Core\Util\Ecc;

use Brick\Math\BigInteger;
use function is_null;
use RuntimeException;

/**
 * @internal
 */
class Curve
{
    /**
     * Elliptic curve over the field of integers modulo a prime.
     *
     * @var BigInteger
     */
    private $a;

    /**
     * @var BigInteger
     */
    private $b;

    /**
     * @var BigInteger
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

    public function __construct(int $size, BigInteger $prime, BigInteger $a, BigInteger $b, Point $generator)
    {
        $this->size = $size;
        $this->prime = $prime;
        $this->a = $a;
        $this->b = $b;
        $this->generator = $generator;
    }

    public function __toString(): string
    {
        return 'curve('.Math::toString($this->getA()).', '.Math::toString($this->getB()).', '.Math::toString($this->getPrime()).')';
    }

    public function getA(): BigInteger
    {
        return $this->a;
    }

    public function getB(): BigInteger
    {
        return $this->b;
    }

    public function getPrime(): BigInteger
    {
        return $this->prime;
    }

    public function getSize(): int
    {
        return $this->size;
    }

    /**
     * @throws RuntimeException if the curve does not contain the point
     */
    public function getPoint(BigInteger $x, BigInteger $y, ?BigInteger $order = null): Point
    {
        if (!$this->contains($x, $y)) {
            throw new RuntimeException('Curve '.$this->__toString().' does not contain point ('.Math::toString($x).', '.Math::toString($y).')');
        }
        $point = Point::create($x, $y, $order);
        if (!is_null($order)) {
            $mul = $this->mul($point, $order);
            if (!$mul->isInfinity()) {
                throw new RuntimeException('SELF * ORDER MUST EQUAL INFINITY.');
            }
        }

        return $point;
    }

    /**
     * @throws RuntimeException if the coordinates are out of range
     */
    public function getPublicKeyFrom(BigInteger $x, BigInteger $y): PublicKey
    {
        $zero = BigInteger::zero();
        if ($x->compareTo($zero) < 0 || $y->compareTo($zero) < 0 || $this->generator->getOrder()->compareTo($x) <= 0 || $this->generator->getOrder()->compareTo($y) <= 0) {
            throw new RuntimeException('Generator point has x and y out of range.');
        }
        $point = $this->getPoint($x, $y);

        return new PublicKey($point);
    }

    public function contains(BigInteger $x, BigInteger $y): bool
    {
        return Math::equals(
            ModularArithmetic::sub(
                $y->power(2),
                Math::add(
                    Math::add(
                        $x->power(3),
                        $this->getA()->multipliedBy($x)
                    ),
                    $this->getB()
                ),
                $this->getPrime()
            ),
            BigInteger::zero()
        );
    }

    public function add(Point $one, Point $two): Point
    {
        if ($two->isInfinity()) {
            return clone $one;
        }

        if ($one->isInfinity()) {
            return clone $two;
        }

        if ($two->getX()->isEqualTo($one->getX())) {
            if ($two->getY()->isEqualTo($one->getY())) {
                return $this->getDouble($one);
            }

            return Point::infinity();
        }

        $slope = ModularArithmetic::div(
            $two->getY()->minus($one->getY()),
            $two->getX()->minus($one->getX()),
            $this->getPrime()
        );

        $xR = ModularArithmetic::sub(
            $slope->power(2)->minus($one->getX()),
            $two->getX(),
            $this->getPrime()
        );

        $yR = ModularArithmetic::sub(
            $slope->multipliedBy($one->getX()->minus($xR)),
            $one->getY(),
            $this->getPrime()
        );

        return $this->getPoint($xR, $yR, $one->getOrder());
    }

    public function mul(Point $one, BigInteger $n): Point
    {
        if ($one->isInfinity()) {
            return Point::infinity();
        }

        /** @var BigInteger $zero */
        $zero = BigInteger::zero();
        if ($one->getOrder()->compareTo($zero) > 0) {
            $n = $n->mod($one->getOrder());
        }

        if ($n->isEqualTo($zero)) {
            return Point::infinity();
        }

        /** @var Point[] $r */
        $r = [
            Point::infinity(),
            clone $one,
        ];

        $k = $this->getSize();
        $n = str_pad(Math::baseConvert(Math::toString($n), 10, 2), $k, '0', STR_PAD_LEFT);

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
        $equal = $this->getA()->isEqualTo($other->getA())
                 && $this->getB()->isEqualTo($other->getB())
                 && $this->getPrime()->isEqualTo($other->getPrime());

        return $equal ? 0 : 1;
    }

    /**
     * @param Curve $other
     */
    public function equals(self $other): bool
    {
        return 0 === $this->cmp($other);
    }

    public function getDouble(Point $point): Point
    {
        if ($point->isInfinity()) {
            return Point::infinity();
        }

        $a = $this->getA();
        $threeX2 = BigInteger::of(3)->multipliedBy($point->getX()->power(2));

        $tangent = ModularArithmetic::div(
            $threeX2->plus($a),
            BigInteger::of(2)->multipliedBy($point->getY()),
            $this->getPrime()
        );

        $x3 = ModularArithmetic::sub(
            $tangent->power(2),
            BigInteger::of(2)->multipliedBy($point->getX()),
            $this->getPrime()
        );

        $y3 = ModularArithmetic::sub(
            $tangent->multipliedBy($point->getX()->minus($x3)),
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

        return new PublicKey($point);
    }

    public function getGenerator(): Point
    {
        return $this->generator;
    }

    /**
     * @throws RuntimeException if the point is invalid
     */
    private function validate(Point $point): void
    {
        if (!$point->isInfinity() && !$this->contains($point->getX(), $point->getY())) {
            throw new RuntimeException('Invalid point');
        }
    }

    private function generate(): BigInteger
    {
        $max = $this->generator->getOrder();
        $numBits = $this->bnNumBits($max);
        $numBytes = (int) ceil($numBits / 8);
        // Generate an integer of size >= $numBits
        $bytes = BigInteger::randomBits($numBytes);
        $mask = BigInteger::of(2)->power($numBits)->minus(1);

        return $bytes->and($mask);
    }

    /**
     * Returns the number of bits used to store this number. Non-significant upper bits are not counted.
     *
     * @see https://www.openssl.org/docs/crypto/BN_num_bytes.html
     */
    private function bnNumBits(BigInteger $x): int
    {
        $zero = BigInteger::of(0);
        if ($x->isEqualTo($zero)) {
            return 0;
        }
        $log2 = 0;
        while (!$x->isEqualTo($zero)) {
            $x = $x->shiftedRight(1);
            ++$log2;
        }

        return $log2;
    }
}
