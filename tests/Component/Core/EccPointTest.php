<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Core;

use Brick\Math\BigInteger;
use Jose\Component\Core\Util\Ecc\Curve;
use Jose\Component\Core\Util\Ecc\EcDH;
use Jose\Component\Core\Util\Ecc\NistCurve;
use Jose\Component\Core\Util\Ecc\Point;
use Jose\Component\Core\Util\Ecc\PrivateKey;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function strlen;
use const STR_PAD_LEFT;

/**
 * Point::cswap used to take the properties of a readonly class by reference, which made every scalar multiplication
 * throw. These tests cover the conditional swap itself and the operations built on top of it.
 *
 * @internal
 */
final class EccPointTest extends TestCase
{
    #[Test]
    public function theConditionalSwapExchangesTheTwoPointsWhenTheConditionIsSet(): void
    {
        $a = Point::create(BigInteger::of(3), BigInteger::of(5), BigInteger::of(7));
        $b = Point::infinity();

        [$swappedA, $swappedB] = Point::cswap($a, $b, 1);

        static::assertTrue($swappedA->isInfinity());
        static::assertFalse($swappedB->isInfinity());
        static::assertTrue($swappedB->getX()->isEqualTo(BigInteger::of(3)));
        static::assertTrue($swappedB->getY()->isEqualTo(BigInteger::of(5)));
        static::assertTrue($swappedB->getOrder()->isEqualTo(BigInteger::of(7)));
    }

    #[Test]
    public function theConditionalSwapKeepsTheTwoPointsWhenTheConditionIsNotSet(): void
    {
        $a = Point::create(BigInteger::of(3), BigInteger::of(5), BigInteger::of(7));
        $b = Point::infinity();

        [$keptA, $keptB] = Point::cswap($a, $b, 0);

        static::assertFalse($keptA->isInfinity());
        static::assertTrue($keptB->isInfinity());
        static::assertTrue($keptA->getX()->isEqualTo(BigInteger::of(3)));
        static::assertTrue($keptA->getY()->isEqualTo(BigInteger::of(5)));
        static::assertTrue($keptA->getOrder()->isEqualTo(BigInteger::of(7)));
    }

    #[Test]
    public function theConditionalSwapLeavesTheGivenPointsUntouched(): void
    {
        $a = Point::create(BigInteger::of(3), BigInteger::of(5), BigInteger::of(7));
        $b = Point::infinity();

        Point::cswap($a, $b, 1);

        static::assertFalse($a->isInfinity());
        static::assertTrue($a->getX()->isEqualTo(BigInteger::of(3)));
        static::assertTrue($b->isInfinity());
    }

    #[Test]
    #[DataProvider('curves')]
    public function theGeneratorMultipliedByItsOrderIsTheInfinity(Curve $curve): void
    {
        $generator = $curve->getGenerator();

        static::assertTrue($curve->mul($generator, $generator->getOrder())->isInfinity());
    }

    /**
     * The key pairs and the shared secrets were produced by OpenSSL.
     */
    #[Test]
    #[DataProvider('keyPairs')]
    public function thePublicKeyComputedByOpensslIsFoundAgain(
        Curve $curve,
        string $privateKey,
        string $x,
        string $y,
        string $peerX,
        string $peerY,
        string $expectedSecret
    ): void {
        $publicKey = $curve->createPublicKey(PrivateKey::create(BigInteger::fromBase($privateKey, 16)));

        static::assertTrue($publicKey->getPoint()->getX()->isEqualTo(BigInteger::fromBase($x, 16)));
        static::assertTrue($publicKey->getPoint()->getY()->isEqualTo(BigInteger::fromBase($y, 16)));
    }

    #[Test]
    #[DataProvider('keyPairs')]
    public function theSharedSecretIsTheOneComputedByOpenssl(
        Curve $curve,
        string $privateKey,
        string $x,
        string $y,
        string $peerX,
        string $peerY,
        string $expectedSecret
    ): void {
        static::assertNotSame($x, $peerX);
        static::assertNotSame($y, $peerY);

        $sharedSecret = EcDH::computeSharedKey(
            $curve,
            $curve->getPublicKeyFrom(BigInteger::fromBase($peerX, 16), BigInteger::fromBase($peerY, 16)),
            PrivateKey::create(BigInteger::fromBase($privateKey, 16))
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
        yield 'P-256' => [NistCurve::curve256()];
        yield 'P-384' => [NistCurve::curve384()];
        yield 'P-521' => [NistCurve::curve521()];
    }

    /**
     * @return iterable<string, array{Curve, string, string, string, string, string, string}>
     */
    public static function keyPairs(): iterable
    {
        yield 'P-256' => [
            NistCurve::curve256(),
            'd24217e163d336415e5de5e6ca91b347975b9e724c5faf9baf6348e3cefcee32',
            'cf3697dd1416399bf340451880833f4a079f9947e723d4eadb7bfbdda0189b7d',
            'c3343bd6745a4674356f4496edc44912ff2a8b43123aa3418ac9c4a3676224ac',
            '8ad8fdb9c9cf93754117ade70489c9c72f499bdb762dc0b4b1ec1bde62d125aa',
            '0c8921842efbea856e4ff4691464f50d916b2f6036b37b713f81912c08a3c911',
            '6e7d837ea69b950234653748d6567d447d09865ce78920f24b98f89bb7754dc6',
        ];

        yield 'P-384' => [
            NistCurve::curve384(),
            '6ebdce3bf8de96541b7e03f5c784dbfbd7e3608b75256a2b318d0697bbe0e58a7ffed1b1b87794c30aaf53997a3f05da',
            '7dd63d67e3e9c90dd5c843495db4bd4ffab5eaa7522e5a2149990e0b8376caeb7686e9ad8585ac88f9c39218eb82f2d5',
            '4e45f17b05451b58390a6b6f720b5d2066f88aab155be190217baddd94ef23cf2972fa3551f553b14f9ec6e6cc47c61f',
            'aba57e60777227dcb258842da33a6da38e7ec0ea946a81fb6831d2bac37b1c6041bbb7b558931059a4ff40e11c60f749',
            '1013a12ff9480976dc641521aedfd5f6b416fb4848ff09379c0214fa52580d73a9071df6b55df4c1410c764fb196f40b',
            'fc8da7854eef964e2d40a5aa900d8cfda9fe8d1b85e6a5b530d2cba793ff3574cf92b1bce44f74cace8b5eeee4ff336b',
        ];

        yield 'P-521' => [
            NistCurve::curve521(),
            '00a9117ddf921446f08a60064b60d06e07687756c3a9bd8af331a3a1aa7d916c448da08dec839205455b812eac76a1e266cd118f2f207f8edcaba1cc750a8d9fcba5',
            '00f4fa0645be2fb177902720e1db522a780dd9e00048c185f235e01a6094e1612adaa655ea81314cc941cb5db736b456c77d7d46e41bf0502de8c6686515358be136',
            '00675cded5ac1eb20d9b27724911110afb482177da76d51e5428d3ad9abbb51e80bb3b15cf99fb88f502b19f716b2cf55a850dde5224e746252446357edffb51ee24',
            '012b39f908ed9c135cb7c5d6ad0757ffc18c63ca3e0fc26427a294fee6ae2d21132941a9a3f12c41f47d78104b88f7ec1bcb28a5c9e56f299645170bf9570194dd82',
            '00b650a42909de7554e03ba25b481292f9b216b1a1e9f7e7559950a380c5b1de7d06f113703e76b8d4137835430583a2426468cdccb567938a9eadbc028ab3defd6a',
            '018a83291a6ec33cc4065a89523a5eeccadcb94e58ea107b13a19f0a9d07eee981a3296aa4902607bd269c59c85ce1c88c1a1ba02ae70dc6d1cf6a8427bc5dc78cc6',
        ];
    }
}
