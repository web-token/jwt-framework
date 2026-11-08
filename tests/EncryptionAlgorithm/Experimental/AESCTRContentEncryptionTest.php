<?php

declare(strict_types=1);

namespace Jose\Tests\EncryptionAlgorithm\ContentEncryption\Experimental;

use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Experimental\KeyEncryption\A128CTR;
use Jose\Experimental\KeyEncryption\A192CTR;
use Jose\Experimental\KeyEncryption\A256CTR;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
final class AESCTRContentEncryptionTest extends TestCase
{
    #[Test]
    public function a128CTRKeyEncryptionAndDecryption(): void
    {
        $header = [];
        $algorithm = new A128CTR();
        $cek = random_bytes(256 / 8);
        $jwk = $this->getKey(128 / 8);

        $additionalHeader = [];
        $encrypted = $algorithm->encryptKey($jwk, $cek, $header, $additionalHeader);
        $decrypted = $algorithm->decryptKey($jwk, $encrypted, $additionalHeader);

        static::assertSame($cek, $decrypted);
    }

    #[Test]
    public function a192CTRKeyEncryptionAndDecryption(): void
    {
        $header = [];
        $algorithm = new A192CTR();
        $cek = random_bytes(256 / 8);
        $jwk = $this->getKey(192 / 8);

        $additionalHeader = [];
        $encrypted = $algorithm->encryptKey($jwk, $cek, $header, $additionalHeader);
        $decrypted = $algorithm->decryptKey($jwk, $encrypted, $additionalHeader);

        static::assertSame($cek, $decrypted);
    }

    #[Test]
    public function a256CTRKeyEncryptionAndDecryption(): void
    {
        $header = [];
        $algorithm = new A256CTR();
        $cek = random_bytes(256 / 8);
        $jwk = $this->getKey(256 / 8);

        $additionalHeader = [];
        $encrypted = $algorithm->encryptKey($jwk, $cek, $header, $additionalHeader);
        $decrypted = $algorithm->decryptKey($jwk, $encrypted, $additionalHeader);

        static::assertSame($cek, $decrypted);
    }

    private function getKey(int $size): JWK
    {
        return new JWK([
            'kty' => 'oct',
            'k' => Base64UrlSafe::encodeUnpadded(random_bytes($size)),
        ]);
    }
}
