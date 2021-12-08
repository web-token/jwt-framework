<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Encryption\Algorithm;

use Jose\Component\Core\JWK;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A128CTR;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A192CTR;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A256CTR;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
final class AESCTRContentEncryptionTest extends TestCase
{
    /**
     * @test
     */
    public function a128CTRKeyEncryptionAndDecryption(): void
    {
        $header = [];
        $algorithm = new A128CTR();
        $cek = random_bytes(256 / 8);
        $jwk = $this->getKey();

        $additionalHeader = [];
        $encrypted = $algorithm->encryptKey($jwk, $cek, $header, $additionalHeader);
        $decrypted = $algorithm->decryptKey($jwk, $encrypted, $additionalHeader);

        static::assertSame($cek, $decrypted);
    }

    /**
     * @test
     */
    public function a192CTRKeyEncryptionAndDecryption(): void
    {
        $header = [];
        $algorithm = new A192CTR();
        $cek = random_bytes(256 / 8);
        $jwk = $this->getKey();

        $additionalHeader = [];
        $encrypted = $algorithm->encryptKey($jwk, $cek, $header, $additionalHeader);
        $decrypted = $algorithm->decryptKey($jwk, $encrypted, $additionalHeader);

        static::assertSame($cek, $decrypted);
    }

    /**
     * @test
     */
    public function a256CTRKeyEncryptionAndDecryption(): void
    {
        $header = [];
        $algorithm = new A256CTR();
        $cek = random_bytes(256 / 8);
        $jwk = $this->getKey();

        $additionalHeader = [];
        $encrypted = $algorithm->encryptKey($jwk, $cek, $header, $additionalHeader);
        $decrypted = $algorithm->decryptKey($jwk, $encrypted, $additionalHeader);

        static::assertSame($cek, $decrypted);
    }

    private function getKey(): JWK
    {
        return new JWK([
            'kty' => 'oct',
            'k' => 'oahUIoWw0K0usKNuOR6H4wkf4oBUXHTxRvgb48E-BVvxkeDNjbC4he8rUWcJoZmds2h7M70imEVhRU5djINXtqllXI4DFqcI1DgjT9LewND8MW2Krf3Spsk_ZkoFnilakGygTwpZ3uesH-PFABNIUYpOiN15dsQRkgr0vEhxN92i2asbOenSZeyaxziK72UwxrrKoExv6kc5twXTq4h-QChLOln0_mtUZwfsRaMStPs6mS6XrgxnxbWhojf663tuEQueGC-FCMfra36C9knDFGzKsNa7LZK2djYgyD3JR_MB_4NUJW_TqOQtwHYbxevoJArm-L5StowjzGy-_bq6Gw',
        ]);
    }
}
