<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Core\Util;

use Jose\Component\Core\Exception\InvalidKeyException;
use Jose\Component\Core\Exception\UnsupportedCurveException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Core\Util\OKPKey;
use Jose\Component\Signature\Algorithm\Ed25519;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function extension_loaded;
use function sprintf;
use function strlen;
use const PHP_VERSION_ID;

/**
 * @internal
 */
final class OKPKeyTest extends TestCase
{
    #[Test]
    public function theOpenSSLBackendNeedsPhp84(): void
    {
        static::assertSame(PHP_VERSION_ID >= 80400 && extension_loaded('openssl'), OKPKey::supportsOpenSSL());
    }

    #[Test]
    public function sodiumOnlyKnowsTheTwoCurve25519Curves(): void
    {
        $loaded = extension_loaded('sodium');

        static::assertSame($loaded, OKPKey::supportsSodium('Ed25519'));
        static::assertSame($loaded, OKPKey::supportsSodium('X25519'));
        static::assertFalse(OKPKey::supportsSodium('Ed448'));
        static::assertFalse(OKPKey::supportsSodium('X448'));
    }

    #[Test]
    public function theCurve448CurvesAreSupportedWithOpenSSLOnly(): void
    {
        static::assertSame(OKPKey::supportsOpenSSL(), OKPKey::isCurveSupported('Ed448'));
        static::assertSame(OKPKey::supportsOpenSSL(), OKPKey::isCurveSupported('X448'));
        static::assertFalse(OKPKey::isCurveSupported('P-256'));
    }

    /**
     * @return iterable<string, array{string, int}>
     */
    public static function curves(): iterable
    {
        yield 'Ed25519' => ['Ed25519', 32];
        yield 'Ed448' => ['Ed448', 57];
        yield 'X25519' => ['X25519', 32];
        yield 'X448' => ['X448', 56];
    }

    #[Test]
    #[DataProvider('curves')]
    public function aKeyIsGeneratedWithTheSizeOfItsCurve(string $curve, int $size): void
    {
        if (! OKPKey::isCurveSupported($curve)) {
            static::markTestSkipped(sprintf('The curve "%s" is not supported on this platform.', $curve));
        }
        $key = OKPKey::generate($curve);

        static::assertSame('OKP', $key->get('kty'));
        static::assertSame($curve, $key->get('crv'));
        static::assertSame($size, strlen(Base64UrlSafe::decodeNoPadding($key->getString('x'))));
        static::assertSame($size, strlen(Base64UrlSafe::decodeNoPadding($key->getString('d'))));
        static::assertSame($size, OKPKey::KEY_SIZES[$curve]);
    }

    #[Test]
    #[DataProvider('curves')]
    public function aKeyIsGeneratedWithOpenSSL(string $curve, int $size): void
    {
        $this->requireOpenSSL();
        $key = OKPKey::generateWithOpenSSL($curve);

        static::assertSame($curve, $key->get('crv'));
        static::assertSame($size, strlen(Base64UrlSafe::decodeNoPadding($key->getString('x'))));
        static::assertSame($size, strlen(Base64UrlSafe::decodeNoPadding($key->getString('d'))));
    }

    #[Test]
    public function anUnknownCurveCannotBeGenerated(): void
    {
        $this->expectException(UnsupportedCurveException::class);
        $this->expectExceptionMessage('Unsupported "Ed455" curve');

        OKPKey::generate('Ed455');
    }

    /**
     * The OpenSSL path of Ed25519 interoperates with the sodium one: the RFC 8037 appendix A.4 signature is
     * reproduced and verified, and a signature made with either backend verifies with the other.
     */
    #[Test]
    public function ed25519SignedWithOpenSSLMatchesTheRfc8037Vector(): void
    {
        $this->requireOpenSSL();
        $key = self::rfc8037Key();
        $input = 'eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc';
        $signature = Base64UrlSafe::decodeNoPadding(
            'hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg'
        );

        static::assertSame($signature, OKPKey::signWithOpenSSL($key, $input));
        static::assertTrue(OKPKey::verifyWithOpenSSL($key->toPublic(), $input, $signature));
        static::assertFalse(OKPKey::verifyWithOpenSSL($key->toPublic(), $input . 'x', $signature));
        static::assertFalse(OKPKey::verifyWithOpenSSL($key->toPublic(), $input, substr($signature, 0, 63)));
    }

    #[Test]
    public function ed25519SignaturesMadeWithOpenSSLAndSodiumAreInterchangeable(): void
    {
        $this->requireOpenSSL();
        if (! extension_loaded('sodium')) {
            static::markTestSkipped('The sodium extension is not loaded.');
        }
        $key = self::rfc8037Key();
        $algorithm = new Ed25519();

        $fromOpenSSL = OKPKey::signWithOpenSSL($key, 'payload');
        $fromSodium = $algorithm->sign($key, 'payload');

        static::assertSame($fromSodium, $fromOpenSSL);
        static::assertTrue($algorithm->verify($key->toPublic(), 'payload', $fromOpenSSL));
        static::assertTrue(OKPKey::verifyWithOpenSSL($key->toPublic(), 'payload', $fromSodium));
    }

    #[Test]
    public function aPublicKeyCannotSignWithOpenSSL(): void
    {
        $this->requireOpenSSL();

        $this->expectException(InvalidKeyException::class);
        OKPKey::signWithOpenSSL(self::rfc8037Key()->toPublic(), 'payload');
    }

    /**
     * RFC 7748 section 6.2: Alice's and Bob's X448 keys and the shared secret K.
     */
    #[Test]
    public function theRfc7748X448VectorIsReproduced(): void
    {
        $this->requireOpenSSL();
        $alice = self::x448Key(
            '9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0',
            '9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b'
        );
        $bob = self::x448Key(
            '3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609',
            '1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d'
        );
        $expected = '07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d';

        static::assertSame($expected, bin2hex(OKPKey::deriveSharedSecret($alice, $bob->toPublic())));
        static::assertSame($expected, bin2hex(OKPKey::deriveSharedSecret($bob, $alice->toPublic())));
        static::assertSame($expected, bin2hex(OKPKey::deriveSharedSecretWithOpenSSL($alice, $bob->toPublic())));
    }

    /**
     * RFC 7748 section 6.1: the X25519 vector, through the sodium path when loaded and the OpenSSL one otherwise,
     * then explicitly through OpenSSL.
     */
    #[Test]
    public function theRfc7748X25519VectorIsReproduced(): void
    {
        if (! OKPKey::isCurveSupported('X25519')) {
            static::markTestSkipped('X25519 is not supported on this platform.');
        }
        $alice = self::x25519Key(
            '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a',
            '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a'
        );
        $bob = self::x25519Key(
            'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f',
            '5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb'
        );
        $expected = '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742';

        static::assertSame($expected, bin2hex(OKPKey::deriveSharedSecret($alice, $bob->toPublic())));
        static::assertSame($expected, bin2hex(OKPKey::deriveSharedSecret($bob, $alice->toPublic())));
        if (OKPKey::supportsOpenSSL()) {
            static::assertSame($expected, bin2hex(OKPKey::deriveSharedSecretWithOpenSSL($alice, $bob->toPublic())));
        }
    }

    #[Test]
    public function theSharedSecretNeedsKeysOnTheSameCurve(): void
    {
        $this->requireOpenSSL();
        $x25519 = OKPKey::generate('X25519');
        $x448 = OKPKey::generate('X448');

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('Curves are different');
        OKPKey::deriveSharedSecret($x25519, $x448->toPublic());
    }

    #[Test]
    public function theSharedSecretIsOnlyDefinedOnTheMontgomeryCurves(): void
    {
        $key = self::rfc8037Key();

        $this->expectException(UnsupportedCurveException::class);
        OKPKey::deriveSharedSecret($key, $key->toPublic());
    }

    private function requireOpenSSL(): void
    {
        if (! OKPKey::supportsOpenSSL()) {
            static::markTestSkipped('OKP keys through OpenSSL need PHP 8.4 or later.');
        }
    }

    private static function rfc8037Key(): JWK
    {
        return new JWK([
            'kty' => 'OKP',
            'crv' => 'Ed25519',
            'd' => 'nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A',
            'x' => '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
        ]);
    }

    private static function x448Key(string $x, string $d): JWK
    {
        return new JWK([
            'kty' => 'OKP',
            'crv' => 'X448',
            'x' => Base64UrlSafe::encodeUnpadded(hex2bin($x)),
            'd' => Base64UrlSafe::encodeUnpadded(hex2bin($d)),
        ]);
    }

    private static function x25519Key(string $x, string $d): JWK
    {
        return new JWK([
            'kty' => 'OKP',
            'crv' => 'X25519',
            'x' => Base64UrlSafe::encodeUnpadded(hex2bin($x)),
            'd' => Base64UrlSafe::encodeUnpadded(hex2bin($d)),
        ]);
    }
}
