<?php

declare(strict_types=1);

namespace Jose\Tests\EncryptionAlgorithm\Experimental;

use InvalidArgumentException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Experimental\KeyEncryption\Chacha20Poly1305;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use function in_array;

/**
 * @internal
 */
final class Chacha20Poly1305KeyEncryptionTest extends TestCase
{
    protected function setUp(): void
    {
        if (! in_array('chacha20-poly1305', openssl_get_cipher_methods(), true)) {
            static::markTestSkipped('The algorithm "chacha20-poly1305" is not supported on this platform.');
        }
    }

    #[Test]
    public function encryptAndDecryptRoundTrip(): void
    {
        $key = $this->key();
        $cek = random_bytes(32);
        $algorithm = new Chacha20Poly1305();

        $additionalHeader = [];
        $encrypted = $algorithm->encryptKey($key, $cek, [], $additionalHeader);

        static::assertArrayHasKey('nonce', $additionalHeader);
        static::assertArrayHasKey('tag', $additionalHeader);

        $decrypted = $algorithm->decryptKey($key, $encrypted, $additionalHeader);
        static::assertSame($cek, $decrypted);
    }

    #[Test]
    public function tamperedCiphertextIsRejected(): void
    {
        $key = $this->key();
        $cek = random_bytes(32);
        $algorithm = new Chacha20Poly1305();

        $additionalHeader = [];
        $encrypted = $algorithm->encryptKey($key, $cek, [], $additionalHeader);

        $encrypted = substr_replace($encrypted, $encrypted[0] ^ "\xff", 0, 1);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Unable to decrypt the CEK');
        $algorithm->decryptKey($key, $encrypted, $additionalHeader);
    }

    #[Test]
    public function tamperedTagIsRejected(): void
    {
        $key = $this->key();
        $cek = random_bytes(32);
        $algorithm = new Chacha20Poly1305();

        $additionalHeader = [];
        $encrypted = $algorithm->encryptKey($key, $cek, [], $additionalHeader);

        $tag = Base64UrlSafe::decodeNoPadding($additionalHeader['tag']);
        $tag = substr_replace($tag, $tag[0] ^ "\xff", 0, 1);
        $additionalHeader['tag'] = Base64UrlSafe::encodeUnpadded($tag);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Unable to decrypt the CEK');
        $algorithm->decryptKey($key, $encrypted, $additionalHeader);
    }

    #[Test]
    public function missingTagIsRejected(): void
    {
        $key = $this->key();
        $cek = random_bytes(32);
        $algorithm = new Chacha20Poly1305();

        $additionalHeader = [];
        $encrypted = $algorithm->encryptKey($key, $cek, [], $additionalHeader);
        unset($additionalHeader['tag']);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The header parameter "tag" is missing.');
        $algorithm->decryptKey($key, $encrypted, $additionalHeader);
    }

    private function key(): JWK
    {
        return new JWK([
            'kty' => 'oct',
            'k' => Base64UrlSafe::encodeUnpadded(random_bytes(32)),
        ]);
    }
}
