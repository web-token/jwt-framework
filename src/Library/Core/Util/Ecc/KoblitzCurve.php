<?php

declare(strict_types=1);

namespace Jose\Component\Core\Util\Ecc;

use Brick\Math\BigInteger;

/**
 * The Koblitz curve secp256k1 (SEC 2 section 2.4.1), registered for JOSE by RFC 8812 section 4 under the "crv" value
 * "secp256k1" and used by the "ES256K" signature algorithm.
 *
 * @internal
 */
final readonly class KoblitzCurve
{
    public static function secp256k1(): Curve
    {
        $p = BigInteger::fromBase('fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f', 16);
        $a = BigInteger::zero();
        $b = BigInteger::of(7);
        $x = BigInteger::fromBase('79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798', 16);
        $y = BigInteger::fromBase('483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8', 16);
        $n = BigInteger::fromBase('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141', 16);
        $generator = Point::create($x, $y, $n);

        return new Curve(256, $p, $a, $b, $generator);
    }
}
