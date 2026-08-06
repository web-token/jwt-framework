<?php

declare(strict_types=1);

namespace Jose\Component\Core\Util\Ecc;

use Brick\Math\BigInteger;
use InvalidArgumentException;
use Jose\Component\Core\Util\BigInteger as CoreBigInteger;

/**
 * @internal
 */
final readonly class Math
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
        return CoreBigInteger::createFromBigInteger($a)->modInverse(CoreBigInteger::createFromBigInteger($m))->get();
    }

    /**
     * @param int<2, 36> $from
     * @param int<2, 36> $to
     */
    public static function baseConvert(string $number, int $from, int $to): string
    {
        if ($number === '') {
            throw new InvalidArgumentException('The number cannot be empty.');
        }

        return BigInteger::fromBase($number, $from)->toBase($to);
    }
}
