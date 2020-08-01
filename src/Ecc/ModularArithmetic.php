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

/**
 * @internal
 */
class ModularArithmetic
{
    public static function sub(BigInteger $minuend, BigInteger $subtrahend, BigInteger $modulus): BigInteger
    {
        return $minuend->minus($subtrahend)->mod($modulus);
    }

    public static function mul(BigInteger $multiplier, BigInteger $muliplicand, BigInteger $modulus): BigInteger
    {
        return $multiplier->multipliedBy($muliplicand)->mod($modulus);
    }

    public static function div(BigInteger $dividend, BigInteger $divisor, BigInteger $modulus): BigInteger
    {
        return self::mul($dividend, Math::inverseMod($divisor, $modulus), $modulus);
    }
}
