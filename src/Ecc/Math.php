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

namespace Jose\Component\Core\Util\Ecc;

use Brick\Math\BigInteger;

/**
 * @internal
 */
class Math
{
    public static function equals(BigInteger $first, BigInteger $other): bool
    {
        return $first->isEqualTo($other);
    }

    public static function add(BigInteger $augend, BigInteger $addend): BigInteger
    {
        return $augend->plus($addend);
    }

    public static function toString(BigInteger $value): string
    {
        return $value->toBase(10);
    }

    public static function inverseMod(BigInteger $a, BigInteger $m): BigInteger
    {
        return gmp_invert($a, $m);
    }

    public static function baseConvert(string $number, int $from, int $to): string
    {
        return BigInteger::fromBase($number, $from)->toBase($to);
    }
}
