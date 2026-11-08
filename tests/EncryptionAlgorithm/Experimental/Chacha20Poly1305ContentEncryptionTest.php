<?php

declare(strict_types=1);

namespace Jose\Tests\EncryptionAlgorithm\ContentEncryption\Experimental;

use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Experimental\KeyEncryption\Chacha20Poly1305;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Throwable;
use function in_array;

/**
 * @internal
 */
final class Chacha20Poly1305ContentEncryptionTest extends TestCase
{
    protected function setUp(): void
    {
        if (! in_array('chacha20-poly1305', openssl_get_cipher_methods(), true)) {
            static::markTestSkipped('The algorithm "chacha20-poly1305" is not supported in this platform.');
        }
    }

    #[Test]
    public function contentEncryptionAndDecryption(): void
    {
        $header = [];
        $algorithm = new Chacha20Poly1305();
        $cek = random_bytes(256 / 8);
        $jwk = $this->getKey();

        $additionalHeader = [];
        try {
            $encrypted = $algorithm->encryptKey($jwk, $cek, $header, $additionalHeader);
            $decrypted = $algorithm->decryptKey($jwk, $encrypted, $additionalHeader);

            static::assertSame($cek, $decrypted);
        } catch (Throwable $e) {
            static::markTestSkipped(sprintf(
                'The algorithm "chacha20-poly1305" is not supported in this platform. Error message: %s',
                $e->getMessage()
            ));
        }
    }

    private function getKey(): JWK
    {
        return new JWK([
            'kty' => 'oct',
            'k' => Base64UrlSafe::encodeUnpadded(random_bytes(256 / 8)),
        ]);
    }
}
