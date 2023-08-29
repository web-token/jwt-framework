<?php

declare(strict_types=1);

namespace Jose\Component\Core\Util\Ecc;

use Brick\Math\BigInteger;
use RuntimeException;
use const STR_PAD_LEFT;
use Stringable;

/**
 * @internal
 */
final class Curve implements Stringable
{
    public function __construct(
        public readonly int $size,
        public readonly BigInteger $prime,
        public readonly BigInteger $a,
        public readonly BigInteger $b,
        public readonly Point $generator
    ) {
    }

    public function __toString(): string
    {
        return 'curve(' . Math::toString($this->a) . ', ' . Math::toString($this->b) . ', ' . Math::toString(
            $this->prime
        ) . ')';
    }

    public function getPoint(BigInteger $x, BigInteger $y, ?BigInteger $order = null): Point
    {
        if (! $this->contains($x, $y)) {
            throw new RuntimeException('Curve ' . $this->__toString() . ' does not contain point (' . Math::toString(
                $x
            ) . ', ' . Math::toString($y) . ')');
        }
        $point = Point::create($x, $y, $order);
        if ($order !== null) {
            $mul = $this->mul($point, $order);
            if (! $mul->infinity) {
                throw new RuntimeException('SELF * ORDER MUST EQUAL INFINITY.');
            }
        }

        return $point;
    }

    public function getPublicKeyFrom(BigInteger $x, BigInteger $y): PublicKey
    {
        $zero = BigInteger::zero();
        if ($x->compareTo($zero) < 0 || $y->compareTo($zero) < 0 || $this->generator->order->compareTo(
            $x
        ) <= 0 || $this->generator->order
            ->compareTo($y) <= 0) {
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
                Math::add(Math::add($x->power(3), $this->a->multipliedBy($x)), $this->b),
                $this->prime
            ),
            BigInteger::zero()
        );
    }

    public function add(Point $one, Point $two): Point
    {
        if ($two->infinity) {
            return clone $one;
        }

        if ($one->infinity) {
            return clone $two;
        }

        if ($two->x->isEqualTo($one->x)) {
            if ($two->y->isEqualTo($one->y)) {
                return $this->getDouble($one);
            }

            return Point::infinity();
        }

        $slope = ModularArithmetic::div($two->y ->minus($one->y), $two->x ->minus($one->x), $this->prime);

        $xR = ModularArithmetic::sub($slope->power(2)->minus($one->x), $two->x, $this->prime);

        $yR = ModularArithmetic::sub($slope->multipliedBy($one->x->minus($xR)), $one->y, $this->prime);

        return $this->getPoint($xR, $yR, $one->order);
    }

    public function mul(Point $one, BigInteger $n): Point
    {
        if ($one->infinity) {
            return Point::infinity();
        }

        /** @var BigInteger $zero */
        $zero = BigInteger::zero();
        if ($one->order->compareTo($zero) > 0) {
            $n = $n->mod($one->order);
        }

        if ($n->isEqualTo($zero)) {
            return Point::infinity();
        }

        /** @var Point[] $r */
        $r = [Point::infinity(), clone $one];

        $k = $this->size;
        $n1 = str_pad(Math::baseConvert(Math::toString($n), 10, 2), $k, '0', STR_PAD_LEFT);

        for ($i = 0; $i < $k; ++$i) {
            $j = $n1[$i];
            Point::cswap($r[0], $r[1], $j ^ 1);
            $r[0] = $this->add($r[0], $r[1]);
            $r[1] = $this->getDouble($r[1]);
            Point::cswap($r[0], $r[1], $j ^ 1);
        }

        $this->validate($r[0]);

        return $r[0];
    }

    public function cmp(self $other): int
    {
        $equalsA = $this->a
            ->isEqualTo($other->a);
        $equalsB = $this->b
            ->isEqualTo($other->b);
        $equalsPrime = $this->prime
            ->isEqualTo($other->prime);
        $equal = $equalsA && $equalsB && $equalsPrime;

        return $equal ? 0 : 1;
    }

    public function equals(self $other): bool
    {
        return $this->cmp($other) === 0;
    }

    public function getDouble(Point $point): Point
    {
        if ($point->infinity) {
            return Point::infinity();
        }

        $a = $this->a;
        $threeX2 = BigInteger::of(3)->multipliedBy($point->x->power(2));

        $tangent = ModularArithmetic::div(
            $threeX2->plus($a),
            BigInteger::of(2)->multipliedBy($point->y),
            $this->prime
        );

        $x3 = ModularArithmetic::sub($tangent->power(2), BigInteger::of(2)->multipliedBy($point->x), $this->prime);

        $y3 = ModularArithmetic::sub($tangent->multipliedBy($point->x->minus($x3)), $point->y, $this->prime);

        return $this->getPoint($x3, $y3, $point->order);
    }

    public function createPrivateKey(): PrivateKey
    {
        return PrivateKey::create($this->generate());
    }

    public function createPublicKey(PrivateKey $privateKey): PublicKey
    {
        $point = $this->mul($this->generator, $privateKey->secret);

        return new PublicKey($point);
    }

    public function getGenerator(): Point
    {
        return $this->generator;
    }

    private function validate(Point $point): void
    {
        if (! $point->infinity && ! $this->contains($point->x, $point->y)) {
            throw new RuntimeException('Invalid point');
        }
    }

    private function generate(): BigInteger
    {
        $max = $this->generator->order;
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
        while (! $x->isEqualTo($zero)) {
            $x = $x->shiftedRight(1);
            ++$log2;
        }

        return $log2;
    }
}
