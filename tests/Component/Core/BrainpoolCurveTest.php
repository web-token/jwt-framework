<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Core;

use Brick\Math\BigInteger;
use Jose\Component\Core\Util\Ecc\BrainpoolCurve;
use Jose\Component\Core\Util\Ecc\Curve;
use Jose\Component\Core\Util\Ecc\EcDH;
use Jose\Component\Core\Util\Ecc\PrivateKey;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;
use function strlen;
use const OPENSSL_KEYTYPE_EC;
use const STR_PAD_LEFT;

/**
 * The domain parameters and the arithmetic are checked against RFC 5639 and against the values OpenSSL computes for
 * the curves it knows under the same names.
 *
 * @internal
 */
final class BrainpoolCurveTest extends TestCase
{
    /**
     * @see https://www.rfc-editor.org/rfc/rfc5639.html#section-3
     */
    #[Test]
    #[DataProvider('domainParameters')]
    public function theDomainParametersAreTheOnesDefinedInRfc5639(
        Curve $curve,
        int $size,
        string $p,
        string $a,
        string $b,
        string $x,
        string $y,
        string $n
    ): void {
        $generator = $curve->getGenerator();

        static::assertSame($size, $curve->getSize());
        static::assertSame($p, $curve->getPrime()->toBase(16));
        static::assertSame($a, $curve->getA()->toBase(16));
        static::assertSame($b, $curve->getB()->toBase(16));
        static::assertSame($x, $generator->getX()->toBase(16));
        static::assertSame($y, $generator->getY()->toBase(16));
        static::assertSame($n, $generator->getOrder()->toBase(16));
    }

    #[Test]
    #[DataProvider('curves')]
    public function theGeneratorLiesOnTheCurveAndHasTheExpectedOrder(Curve $curve): void
    {
        $generator = $curve->getGenerator();

        static::assertTrue($curve->contains($generator->getX(), $generator->getY()));
        static::assertTrue($curve->mul($generator, $generator->getOrder())->isInfinity());
    }

    /**
     * The key pair produced by OpenSSL for the same named curve must be found again by the pure PHP implementation,
     * which checks all the domain parameters against the ones OpenSSL uses.
     */
    #[Test]
    #[DataProvider('curves')]
    public function thePublicKeyGeneratedByOpensslIsComputedAgain(Curve $curve): void
    {
        $key = openssl_pkey_new([
            'curve_name' => sprintf('brainpoolP%dr1', $curve->getSize()),
            'private_key_type' => OPENSSL_KEYTYPE_EC,
        ]);
        static::assertNotFalse($key);
        $details = openssl_pkey_get_details($key);
        static::assertIsArray($details);

        $publicKey = $curve->createPublicKey(PrivateKey::create(self::toBigInteger($details['ec']['d'])));

        static::assertTrue($publicKey->getPoint()->getX()->isEqualTo(self::toBigInteger($details['ec']['x'])));
        static::assertTrue($publicKey->getPoint()->getY()->isEqualTo(self::toBigInteger($details['ec']['y'])));
    }

    /**
     * The expected shared secrets were produced by OpenSSL with the very same key pairs.
     */
    #[Test]
    #[DataProvider('sharedSecrets')]
    public function theSharedSecretIsTheOneComputedByOpenssl(
        Curve $curve,
        string $senderPrivateKey,
        string $recipientX,
        string $recipientY,
        string $expectedSecret
    ): void {
        $sharedSecret = EcDH::computeSharedKey(
            $curve,
            $curve->getPublicKeyFrom(BigInteger::fromBase($recipientX, 16), BigInteger::fromBase($recipientY, 16)),
            PrivateKey::create(BigInteger::fromBase($senderPrivateKey, 16))
        );

        static::assertSame(
            $expectedSecret,
            str_pad($sharedSecret->toBase(16), strlen($expectedSecret), '0', STR_PAD_LEFT)
        );
    }

    /**
     * @return iterable<string, array{Curve}>
     */
    public static function curves(): iterable
    {
        yield 'brainpoolP256r1' => [BrainpoolCurve::curve256()];
        yield 'brainpoolP384r1' => [BrainpoolCurve::curve384()];
        yield 'brainpoolP512r1' => [BrainpoolCurve::curve512()];
    }

    /**
     * @return iterable<string, array{Curve, int, string, string, string, string, string, string}>
     */
    public static function domainParameters(): iterable
    {
        yield 'brainpoolP256r1' => [
            BrainpoolCurve::curve256(),
            256,
            'a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377',
            '7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9',
            '26dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b6',
            '8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262',
            '547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997',
            'a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7',
        ];

        yield 'brainpoolP384r1' => [
            BrainpoolCurve::curve384(),
            384,
            '8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53',
            '7bc382c63d8c150c3c72080ace05afa0c2bea28e4fb22787139165efba91f90f8aa5814a503ad4eb04a8c7dd22ce2826',
            '4a8c7dd22ce28268b39b55416f0447c2fb77de107dcd2a62e880ea53eeb62d57cb4390295dbc9943ab78696fa504c11',
            '1d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e247d4af1e',
            '8abe1d7520f9c2a45cb1eb8e95cfd55262b70b29feec5864e19c054ff99129280e4646217791811142820341263c5315',
            '8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565',
        ];

        yield 'brainpoolP512r1' => [
            BrainpoolCurve::curve512(),
            512,
            'aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3',
            '7830a3318b603b89e2327145ac234cc594cbdd8d3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94ca',
            '3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94cadc083e67984050b75ebae5dd2809bd638016f723',
            '81aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d0098eff3b1f78e2d0d48d50d1687b93b97d5f7c6d5047406a5e688b352209bcb9f822',
            '7dde385d566332ecc0eabfa9cf7822fdf209f70024a57b1aa000c55b881f8111b2dcde494a5f485e5bca4bd88a2763aed1ca2b2fa8f0540678cd1e0f3ad80892',
            'aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069',
        ];
    }

    /**
     * @return iterable<string, array{Curve, string, string, string, string}>
     */
    public static function sharedSecrets(): iterable
    {
        yield 'brainpoolP256r1' => [
            BrainpoolCurve::curve256(),
            '0ddd1ab28153085ebaeb7e23dbcbe836cd54e99e51bda1fc6716baf3b94cdc14',
            'a4ecd9706fb915b51953218aad7826f98b0790848c0f2c495b8142e5898da0a5',
            '9e41225d3f915acabc8b1720e8e6bc743e5b6c04f12ec98dd846732a5b717355',
            '06a2950936aa1eb2d39afdfdebd333a13be31844eacd90a8783ba1f8d67454de',
        ];

        yield 'brainpoolP384r1' => [
            BrainpoolCurve::curve384(),
            '1f9f6fb9792bccc786791e13a7a481e048ee350441f78306101bbd259565bb6489f9ffb1868953fbdb872e5f1499d124',
            '490b614fa0eade2afb8d4f7938df761205834a36c30eda9b3e9b25b6555cfea129e4ba487615bd7a75ca6e44a516e076',
            '4d6c677d71f4e5a602586c69899da792ef3385bfe7481721b9f53ec4641c26b793913ad5e5256d96e06bc525838cc5aa',
            '5c0e589eeea53b2f8b9a599b55a6b98a812f2139d478de57951666c58e6cd8b4171ed5372d170e73ff4b8dc270317286',
        ];

        yield 'brainpoolP512r1' => [
            BrainpoolCurve::curve512(),
            '2057ef8553670b8bc87fc008b9aad7e00637340a0e85c4aefba85cadb23684eff838158ed51f766462bbc010336821b6d30de810820a9f63c3fb9a00e54f0ef1',
            '6ef2d502e3c306e342c647a128625892fc18f89b7068ac0c3d071f5e8b525a203567addf831c8dc1cf3d0fce92a1de00e8abdd523cffca884969d09a4de2e1a2',
            '8215f0510cdcf0a6432b5ef7ffbd6f03faea0c0a2d5f3a4dad1f6843b8a6ffe962528fb043c3b6f9b5237fcac6ae633a981211a17e9a79f647715c409ed5f493',
            '0996145a819bc7ddcb0500881cf15783c1beb0c0d09e164fc1aa02ebc5622d0ed69511b419e66d01b1eca0cdb3d3b5ee779faec774b202711ada164e488b11c6',
        ];
    }

    private static function toBigInteger(string $value): BigInteger
    {
        return BigInteger::fromBase(bin2hex($value), 16);
    }
}
