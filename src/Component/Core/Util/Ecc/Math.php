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
class Math
{
    /**
     * @param \GMP $first
     * @param \GMP $other
     *
     * @return int
     */
    public static function cmp(\GMP $first, \GMP $other): int
    {
        return gmp_cmp($first, $other);
    }

    /**
     * @param \GMP $first
     * @param \GMP $other
     *
     * @return bool
     */
    public static function equals(\GMP $first, \GMP $other): bool
    {
        return 0 === gmp_cmp($first, $other);
    }

    /**
     * @param \GMP $number
     * @param \GMP $modulus
     *
     * @return \GMP
     */
    public static function mod(\GMP $number, \GMP $modulus): \GMP
    {
        return gmp_mod($number, $modulus);
    }

    /**
     * @param \GMP $augend
     * @param \GMP $addend
     *
     * @return \GMP
     */
    public static function add(\GMP $augend, \GMP $addend): \GMP
    {
        return gmp_add($augend, $addend);
    }

    /**
     * @param \GMP $minuend
     * @param \GMP $subtrahend
     *
     * @return \GMP
     */
    public static function sub(\GMP $minuend, \GMP $subtrahend): \GMP
    {
        return gmp_sub($minuend, $subtrahend);
    }

    /**
     * @param \GMP $multiplier
     * @param \GMP $multiplicand
     *
     * @return \GMP
     */
    public static function mul(\GMP $multiplier, \GMP $multiplicand): \GMP
    {
        return gmp_mul($multiplier, $multiplicand);
    }

    /**
     * @param \GMP $base
     * @param int  $exponent
     *
     * @return \GMP
     */
    public static function pow(\GMP $base, int $exponent): \GMP
    {
        return gmp_pow($base, $exponent);
    }

    /**
     * @param \GMP $first
     * @param \GMP $other
     *
     * @return \GMP
     */
    public static function bitwiseAnd(\GMP $first, \GMP $other): \GMP
    {
        return gmp_and($first, $other);
    }

    /**
     * @param \GMP $first
     * @param \GMP $other
     *
     * @return \GMP
     */
    public static function bitwiseXor(\GMP $first, \GMP $other): \GMP
    {
        return gmp_xor($first, $other);
    }

    /**
     * @param \GMP $value
     *
     * @return string
     */
    public static function toString(\GMP $value): string
    {
        return gmp_strval($value);
    }

    /**
     * @param \GMP $a
     * @param \GMP $m
     *
     * @return \GMP
     */
    public static function inverseMod(\GMP $a, \GMP $m): \GMP
    {
        return gmp_invert($a, $m);
    }

    /**
     * @param string $number
     * @param int    $from
     * @param int    $to
     *
     * @return string
     */
    public static function baseConvert(string $number, int $from, int $to): string
    {
        return gmp_strval(gmp_init($number, $from), $to);
    }

    /**
     * @param \GMP $number
     * @param int  $positions
     *
     * @return \GMP
     */
    public static function rightShift(\GMP $number, int $positions): \GMP
    {
        return gmp_div($number, gmp_pow(gmp_init(2, 10), $positions));
    }

    /**
     * @param string $s
     *
     * @return \GMP
     */
    public static function stringToInt(string $s): \GMP
    {
        $result = gmp_init(0, 10);
        $sLen = mb_strlen($s, '8bit');

        for ($c = 0; $c < $sLen; $c++) {
            $result = gmp_add(gmp_mul(256, $result), gmp_init(ord($s[$c]), 10));
        }

        return $result;
    }
}
