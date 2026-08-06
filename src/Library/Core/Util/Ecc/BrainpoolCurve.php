<?php

declare(strict_types=1);

namespace Jose\Component\Core\Util\Ecc;

use Brick\Math\BigInteger;

/**
 * Domain parameters of the regular ECC Brainpool curves defined in RFC 5639, section 3.
 *
 * These curves have no IANA registration in the "JSON Web Key Elliptic Curve" registry. The identifiers "BP-256",
 * "BP-384" and "BP-512" used by this library follow the de facto convention adopted by the existing implementations.
 *
 * @internal
 */
final readonly class BrainpoolCurve
{
    /**
     * Returns the brainpoolP256r1 curve.
     */
    public static function curve256(): Curve
    {
        $p = BigInteger::fromBase('a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377', 16);
        $a = BigInteger::fromBase('7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9', 16);
        $b = BigInteger::fromBase('26dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b6', 16);
        $x = BigInteger::fromBase('8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262', 16);
        $y = BigInteger::fromBase('547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997', 16);
        $n = BigInteger::fromBase('a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7', 16);
        $generator = Point::create($x, $y, $n);

        return new Curve(256, $p, $a, $b, $generator);
    }

    /**
     * Returns the brainpoolP384r1 curve.
     */
    public static function curve384(): Curve
    {
        $p = BigInteger::fromBase(
            '8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53',
            16
        );
        $a = BigInteger::fromBase(
            '7bc382c63d8c150c3c72080ace05afa0c2bea28e4fb22787139165efba91f90f8aa5814a503ad4eb04a8c7dd22ce2826',
            16
        );
        $b = BigInteger::fromBase(
            '04a8c7dd22ce28268b39b55416f0447c2fb77de107dcd2a62e880ea53eeb62d57cb4390295dbc9943ab78696fa504c11',
            16
        );
        $x = BigInteger::fromBase(
            '1d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e247d4af1e',
            16
        );
        $y = BigInteger::fromBase(
            '8abe1d7520f9c2a45cb1eb8e95cfd55262b70b29feec5864e19c054ff99129280e4646217791811142820341263c5315',
            16
        );
        $n = BigInteger::fromBase(
            '8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565',
            16
        );
        $generator = Point::create($x, $y, $n);

        return new Curve(384, $p, $a, $b, $generator);
    }

    /**
     * Returns the brainpoolP512r1 curve.
     */
    public static function curve512(): Curve
    {
        $p = BigInteger::fromBase(
            'aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3',
            16
        );
        $a = BigInteger::fromBase(
            '7830a3318b603b89e2327145ac234cc594cbdd8d3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94ca',
            16
        );
        $b = BigInteger::fromBase(
            '3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94cadc083e67984050b75ebae5dd2809bd638016f723',
            16
        );
        $x = BigInteger::fromBase(
            '81aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d0098eff3b1f78e2d0d48d50d1687b93b97d5f7c6d5047406a5e688b352209bcb9f822',
            16
        );
        $y = BigInteger::fromBase(
            '7dde385d566332ecc0eabfa9cf7822fdf209f70024a57b1aa000c55b881f8111b2dcde494a5f485e5bca4bd88a2763aed1ca2b2fa8f0540678cd1e0f3ad80892',
            16
        );
        $n = BigInteger::fromBase(
            'aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069',
            16
        );
        $generator = Point::create($x, $y, $n);

        return new Curve(512, $p, $a, $b, $generator);
    }
}
