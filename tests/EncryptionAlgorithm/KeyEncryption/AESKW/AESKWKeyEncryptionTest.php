<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Encryption\Algorithm\KeyEncryption;

use InvalidArgumentException;
use Jose\Component\Core\JWK;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A128KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A192KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A256KW;
use ParagonIE\ConstantTime\Base64UrlSafe;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
final class AESKWKeyEncryptionTest extends TestCase
{
    /**
     * @test
     */
    public function a128KW(): void
    {
        $header = [];
        $key = new JWK([
            'kty' => 'oct',
            'k' => Base64UrlSafe::encodeUnpadded(hex2bin('000102030405060708090A0B0C0D0E0F')),
        ]);

        $cek = hex2bin('00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F');

        $aeskw = new A128KW();

        $wrapped_cek = $aeskw->wrapKey($key, $cek, $header, $header);

        static::assertSame(
            $wrapped_cek,
            hex2bin('11826840774D993FF9C2FA02CCA3CEA0E93B1E1CF96361F93EA6DC2F345194E7B30F964C79F9E61D')
        );
        static::assertSame($cek, $aeskw->unwrapKey($key, $wrapped_cek, $header));
    }

    /**
     * @test
     */
    public function badKey(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Wrong key type');

        $header = [];
        $key = new JWK([
            'kty' => 'EC',
        ]);

        $cek = hex2bin('00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F');

        $aeskw = new A128KW();

        $aeskw->wrapKey($key, $cek, $header, $header);
    }

    /**
     * @test
     */
    public function a192KW(): void
    {
        $header = [];
        $key = new JWK([
            'kty' => 'oct',
            'k' => Base64UrlSafe::encodeUnpadded(hex2bin('000102030405060708090A0B0C0D0E0F1011121314151617')),
        ]);

        $cek = hex2bin('00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F');

        $aeskw = new A192KW();

        $wrapped_cek = $aeskw->wrapKey($key, $cek, $header, $header);

        static::assertSame(
            $wrapped_cek,
            hex2bin('08861E000AABFA4479C7191F9DC51CCA37C50F16CC14441C6EA4980CFCE0F41D9285758C6F74AC6D')
        );
        static::assertSame($cek, $aeskw->unwrapKey($key, $wrapped_cek, $header));
    }

    /**
     * @test
     */
    public function a256KW(): void
    {
        $header = [];
        $key = new JWK([
            'kty' => 'oct',
            'k' => Base64UrlSafe::encodeUnpadded(
                hex2bin('000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F')
            ),
        ]);

        $cek = hex2bin('00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F');

        $aeskw = new A256KW();

        $wrapped_cek = $aeskw->wrapKey($key, $cek, $header, $header);

        static::assertSame(
            $wrapped_cek,
            hex2bin('28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21')
        );
        static::assertSame($cek, $aeskw->unwrapKey($key, $wrapped_cek, $header));
    }
}
