<?php

declare(strict_types=1);

namespace Jose\Component\Core\Util\Ecc;

use Brick\Math\BigInteger;
use InvalidArgumentException;
use function strlen;
use const STR_PAD_LEFT;

/**
 * Copyright (C) 2012 Matyas Danter.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
 * documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
 * WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

/**
 * @internal
 */
final readonly class Point
{
    private function __construct(
        private BigInteger $x,
        private BigInteger $y,
        private BigInteger $order,
        private bool $infinity = false
    ) {
    }

    public static function create(BigInteger $x, BigInteger $y, ?BigInteger $order = null): self
    {
        return new self($x, $y, $order ?? BigInteger::zero());
    }

    public static function infinity(): self
    {
        $zero = BigInteger::zero();

        return new self($zero, $zero, $zero, true);
    }

    public function isInfinity(): bool
    {
        return $this->infinity;
    }

    public function getOrder(): BigInteger
    {
        return $this->order;
    }

    public function getX(): BigInteger
    {
        return $this->x;
    }

    public function getY(): BigInteger
    {
        return $this->y;
    }

    /**
     * Returns both points, swapped when the condition is 1 and unchanged when it is 0.
     *
     * The points are rebuilt instead of being mutated in place: this class is readonly, so its properties cannot be
     * taken by reference.
     *
     * @return array{self, self}
     */
    public static function cswap(self $a, self $b, int $cond): array
    {
        [$xA, $xB] = self::cswapBigInteger($a->x, $b->x, $cond);
        [$yA, $yB] = self::cswapBigInteger($a->y, $b->y, $cond);
        [$orderA, $orderB] = self::cswapBigInteger($a->order, $b->order, $cond);
        [$infinityA, $infinityB] = self::cswapBoolean($a->infinity, $b->infinity, $cond);

        return [new self($xA, $yA, $orderA, $infinityA), new self($xB, $yB, $orderB, $infinityB)];
    }

    /**
     * @return array{bool, bool}
     */
    private static function cswapBoolean(bool $a, bool $b, int $cond): array
    {
        [$sa, $sb] = self::cswapBigInteger(BigInteger::of((int) $a), BigInteger::of((int) $b), $cond);

        return [(bool) $sa->toBase(10), (bool) $sb->toBase(10)];
    }

    /**
     * The mask is as wide as the longer of the two operands, so it is never empty; the guard is there because
     * `BigInteger::fromBase()` requires a non-empty string and the width cannot be proven statically.
     *
     * @return array{BigInteger, BigInteger}
     */
    private static function cswapBigInteger(BigInteger $sa, BigInteger $sb, int $cond): array
    {
        $size = max(strlen($sa->toBase(2)), strlen($sb->toBase(2)));
        $bits = str_pad('', $size, (string) (1 - $cond), STR_PAD_LEFT);
        if ($bits === '') {
            throw new InvalidArgumentException('Unable to compute the mask');
        }
        $mask = BigInteger::fromBase($bits, 2);
        $taA = $sa->and($mask);
        $taB = $sb->and($mask);
        $sa = $sa->xor($sb)
            ->xor($taB);
        $sb = $sa->xor($sb)
            ->xor($taA);
        $sa = $sa->xor($sb)
            ->xor($taB);

        return [$sa, $sb];
    }
}
