<?php

declare(strict_types=1);

namespace Jose\Tests\EncryptionAlgorithm\KeyEncryption\AESGCMKW;

use InvalidArgumentException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A128GCMKW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A192GCMKW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A256GCMKW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\AESGCMKW;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use function sprintf;

/**
 * @internal
 */
final class AESGCMKWKeyEncryptionTest extends TestCase
{
    #[Test]
    public function a128GCMKW(): void
    {
        $header = [];
        $key = new JWK([
            'kty' => 'oct',
            'k' => Base64UrlSafe::encodeUnpadded(hex2bin('000102030405060708090A0B0C0D0E0F')),
        ]);

        $cek = hex2bin('00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F');

        $aeskw = new A128GCMKW();

        $wrapped_cek = $aeskw->wrapKey($key, $cek, $header, $header);

        static::assertArrayHasKey('iv', $header);
        static::assertArrayHasKey('tag', $header);
        static::assertNotNull($header['iv']);
        static::assertNotNull($header['tag']);
        static::assertSame($cek, $aeskw->unwrapKey($key, $wrapped_cek, $header));
    }

    #[Test]
    public function badKey(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Wrong key type.');

        $header = [];
        $key = new JWK([
            'kty' => 'EC',
        ]);

        $cek = hex2bin('00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F');

        $aeskw = new A128GCMKW();

        $aeskw->wrapKey($key, $cek, $header, $header);
    }

    #[Test]
    public function missingParameters(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Parameter "iv" is missing.');

        $header = [];
        $key = new JWK([
            'kty' => 'oct',
            'k' => Base64UrlSafe::encodeUnpadded(hex2bin('000102030405060708090A0B0C0D0E0F')),
        ]);

        $cek = hex2bin('00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F');

        $aeskw = new A128GCMKW();

        $aeskw->unwrapKey($key, $cek, $header);
    }

    #[Test]
    public function a192GCMKW(): void
    {
        $header = [];
        $key = new JWK([
            'kty' => 'oct',
            'k' => Base64UrlSafe::encodeUnpadded(hex2bin('000102030405060708090A0B0C0D0E0F1011121314151617')),
        ]);

        $cek = hex2bin('00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F');

        $aeskw = new A192GCMKW();

        $wrapped_cek = $aeskw->wrapKey($key, $cek, $header, $header);

        static::assertArrayHasKey('iv', $header);
        static::assertArrayHasKey('tag', $header);
        static::assertNotNull($header['iv']);
        static::assertNotNull($header['tag']);
        static::assertSame($cek, $aeskw->unwrapKey($key, $wrapped_cek, $header));
    }

    #[Test]
    public function a256GCMKW(): void
    {
        $header = [];
        $key = new JWK([
            'kty' => 'oct',
            'k' => Base64UrlSafe::encodeUnpadded(
                hex2bin('000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F')
            ),
        ]);

        $cek = hex2bin('00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F');

        $aeskw = new A256GCMKW();

        $wrapped_cek = $aeskw->wrapKey($key, $cek, $header, $header);

        static::assertArrayHasKey('iv', $header);
        static::assertArrayHasKey('tag', $header);
        static::assertNotNull($header['iv']);
        static::assertNotNull($header['tag']);
        static::assertSame($cek, $aeskw->unwrapKey($key, $wrapped_cek, $header));
    }

    #[DataProvider('dataTruncatedTags')]
    #[Test]
    public function truncatedTagIsRejected(AESGCMKW $algorithm, int $keySize, int $length): void
    {
        $header = [];
        $key = new JWK([
            'kty' => 'oct',
            'k' => Base64UrlSafe::encodeUnpadded(random_bytes($keySize)),
        ]);
        $cek = random_bytes(32);

        $wrapped_cek = $algorithm->wrapKey($key, $cek, $header, $header);
        $tag = Base64UrlSafe::decodeNoPadding($header['tag']);
        $header['tag'] = Base64UrlSafe::encodeUnpadded(mb_substr($tag, 0, $length, '8bit'));

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Unable to decrypt the CEK');

        $algorithm->unwrapKey($key, $wrapped_cek, $header);
    }

    public static function dataTruncatedTags(): iterable
    {
        foreach ([[new A128GCMKW(), 16], [new A192GCMKW(), 24], [new A256GCMKW(), 32]] as [$algorithm, $keySize]) {
            foreach ([0, 1, 4, 8, 12, 15] as $length) {
                yield sprintf('%s, %d bytes', $algorithm->name(), $length) => [$algorithm, $keySize, $length];
            }
        }
    }
}
