<?php

declare(strict_types=1);

namespace Jose\Tests\Component\KeyManagement\Keys;

use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Core\Util\ECKey;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\KeyManagement\KeyConverter\KeyConverter;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function strlen;
use const DIRECTORY_SEPARATOR;

/**
 * @internal
 */
final class BrainpoolKeysTest extends TestCase
{
    #[Test]
    #[DataProvider('curves')]
    public function aKeyIsCreatedOnTheExpectedCurve(string $curve, string $file, int $size): void
    {
        $jwk = (new JWKFactory())->ec($curve);

        static::assertSame('EC', $jwk->get('kty'));
        static::assertSame($curve, $jwk->get('crv'));
        static::assertSame($size, strlen(Base64UrlSafe::decodeNoPadding(self::getString($jwk, 'x'))));
        static::assertSame($size, strlen(Base64UrlSafe::decodeNoPadding(self::getString($jwk, 'y'))));
        static::assertSame($size, strlen(Base64UrlSafe::decodeNoPadding(self::getString($jwk, 'd'))));
    }

    #[Test]
    #[DataProvider('curves')]
    public function aPrivateKeyIsLoadedFromPem(string $curve, string $file, int $size): void
    {
        $values = KeyConverter::loadFromKeyFile(self::path('private.' . $file . '.key'));

        static::assertSame('EC', $values['kty']);
        static::assertSame($curve, $values['crv']);
        static::assertSame($size, strlen(Base64UrlSafe::decodeNoPadding($values['d'])));
    }

    #[Test]
    #[DataProvider('curves')]
    public function aPublicKeyIsLoadedFromPem(string $curve, string $file, int $size): void
    {
        $values = KeyConverter::loadFromKeyFile(self::path('public.' . $file . '.key'));

        static::assertSame('EC', $values['kty']);
        static::assertSame($curve, $values['crv']);
        static::assertArrayNotHasKey('d', $values);
    }

    /**
     * The public part of the private PEM file must match the public PEM file of the same key pair.
     */
    #[Test]
    #[DataProvider('curves')]
    public function thePublicAndThePrivatePemFilesDescribeTheSameKey(string $curve, string $file, int $size): void
    {
        $private = KeyConverter::loadFromKeyFile(self::path('private.' . $file . '.key'));
        $public = KeyConverter::loadFromKeyFile(self::path('public.' . $file . '.key'));

        static::assertSame($curve, $private['crv']);
        static::assertSame($public['x'], $private['x']);
        static::assertSame($public['y'], $private['y']);
    }

    #[Test]
    #[DataProvider('curves')]
    public function aKeyIsConvertedToPemAndLoadedAgain(string $curve, string $file, int $size): void
    {
        $jwk = (new JWKFactory())->ec($curve);

        $private = KeyConverter::loadFromKey(ECKey::convertToPEM($jwk));
        $public = KeyConverter::loadFromKey(ECKey::convertToPEM($jwk->toPublic()));

        static::assertSame(
            [
                'kty' => 'EC',
                'crv' => $curve,
                'd' => $jwk->get('d'),
                'x' => $jwk->get('x'),
                'y' => $jwk->get('y'),
            ],
            $private
        );
        static::assertSame([
            'kty' => 'EC',
            'crv' => $curve,
            'x' => $jwk->get('x'),
            'y' => $jwk->get('y'),
        ], $public);
    }

    /**
     * @return iterable<string, array{string, string, int}>
     */
    public static function curves(): iterable
    {
        yield 'BP-256' => ['BP-256', 'bp256r1', 32];
        yield 'BP-384' => ['BP-384', 'bp384r1', 48];
        yield 'BP-512' => ['BP-512', 'bp512r1', 64];
    }

    private static function path(string $file): string
    {
        return 'file://' . __DIR__ . DIRECTORY_SEPARATOR . 'EC' . DIRECTORY_SEPARATOR . $file;
    }

    private static function getString(JWK $jwk, string $key): string
    {
        $value = $jwk->get($key);
        static::assertIsString($value);

        return $value;
    }
}
