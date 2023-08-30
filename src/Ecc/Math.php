<?php

declare(strict_types=1);

namespace Jose\Component\Core\Util\Ecc;

use Brick\Math\BigInteger;
use Jose\Component\Core\Util\BigInteger as CoreBigInteger;

/**
 * @internal
 */
final class Math
{
    public static function add(BigInteger $augend, BigInteger $addend): BigInteger
    {
        return $augend->plus($addend);
    }

    public static function inverseMod(BigInteger $a, BigInteger $m): BigInteger
    {
        return CoreBigInteger::createFromBigInteger($a)->modInverse(CoreBigInteger::createFromBigInteger($m))->get();
    }
}
