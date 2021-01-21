<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Tests\Component\Encryption\Algorithm\KeyEncryption;

use Base64Url\Base64Url;
use InvalidArgumentException;
use Jose\Component\Core\JWK;
use Jose\Component\Encryption\Algorithm\KeyEncryption\PBES2HS256A128KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\PBES2HS384A192KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\PBES2HS512A256KW;
use PHPUnit\Framework\TestCase;

/**
 * Class PBES2_HS_AESKWKeyEncryptionTest.
 *
 * @group PBES2HSAESKW
 * @group unit
 *
 * @internal
 */
class PBES2_HS_AESKWKeyEncryptionTest extends TestCase
{
    /**
     * @see https://tools.ietf.org/html/rfc7517#appendix-C
     *
     * @test
     */
    public function pBES2HS256A128KW(): void
    {
        $header = [
            'alg' => 'PBES2-HS256+A128KW',
            'p2s' => '2WCTcJZ1Rvd_CJuJripQ1w',
            'p2c' => 4096,
            'enc' => 'A128CBC-HS256',
            'cty' => 'jwk+json',
        ];
        $key = new JWK([
            'kty' => 'oct',
            'k' => Base64Url::encode($this->convertArrayToBinString([84, 104, 117, 115, 32, 102, 114, 111, 109, 32, 109, 121, 32, 108, 105, 112, 115, 44, 32, 98, 121, 32, 121, 111, 117, 114, 115, 44, 32, 109, 121, 32, 115, 105, 110, 32, 105, 115, 32, 112, 117, 114, 103, 101, 100, 46])),
        ]);

        $expected_cek = $this->convertArrayToBinString([111, 27, 25, 52, 66, 29, 20, 78, 92, 176, 56, 240, 65, 208, 82, 112, 161, 131, 36, 55, 202, 236, 185, 172, 129, 23, 153, 194, 195, 48, 253, 182]);

        $pbes2 = new PBES2HS256A128KW();

        $wrapped_cek = Base64Url::decode('TrqXOwuNUfDV9VPTNbyGvEJ9JMjefAVn-TR1uIxR9p6hsRQh9Tk7BA');

        static::assertEquals($expected_cek, $pbes2->unwrapKey($key, $wrapped_cek, $header));
    }

    /**
     * @test
     */
    public function pBES2HS256A128KWBis(): void
    {
        $header = [
            'alg' => 'PBES2-HS256+A128KW',
            'enc' => 'A128CBC-HS256',
            'cty' => 'jwk+json',
        ];
        $key = new JWK([
            'kty' => 'oct',
            'k' => Base64Url::encode($this->convertArrayToBinString([84, 104, 117, 115, 32, 102, 114, 111, 109, 32, 109, 121, 32, 108, 105, 112, 115, 44, 32, 98, 121, 32, 121, 111, 117, 114, 115, 44, 32, 109, 121, 32, 115, 105, 110, 32, 105, 115, 32, 112, 117, 114, 103, 101, 100, 46])),
        ]);

        $cek = $this->convertArrayToBinString([111, 27, 25, 52, 66, 29, 20, 78, 92, 176, 56, 240, 65, 208, 82, 112, 161, 131, 36, 55, 202, 236, 185, 172, 129, 23, 153, 194, 195, 48, 253, 182]);

        $pbes2 = new PBES2HS256A128KW();
        $encrypted_cek = $pbes2->wrapKey($key, $cek, $header, $header);
        static::assertTrue(isset($header['p2s']));
        static::assertEquals(4096, $header['p2c']);
        static::assertEquals($cek, $pbes2->unwrapKey($key, $encrypted_cek, $header));
    }

    /**
     * @test
     */
    public function pBES2HS384A192KW(): void
    {
        $header = [
            'alg' => 'PBES2-HS384+A192KW',
            'enc' => 'A192CBC-HS384',
            'cty' => 'jwk+json',
        ];
        $key = new JWK([
            'kty' => 'oct',
            'k' => Base64Url::encode($this->convertArrayToBinString([84, 104, 117, 115, 32, 102, 114, 111, 109, 32, 109, 121, 32, 108, 105, 112, 115, 44, 32, 98, 121, 32, 121, 111, 117, 114, 115, 44, 32, 109, 121, 32, 115, 105, 110, 32, 105, 115, 32, 112, 117, 114, 103, 101, 100, 46])),
        ]);

        $cek = $this->convertArrayToBinString([111, 27, 25, 52, 66, 29, 20, 78, 92, 176, 56, 240, 65, 208, 82, 112, 161, 131, 36, 55, 202, 236, 185, 172, 129, 23, 153, 194, 195, 48, 253, 182]);

        $pbes2 = new PBES2HS384A192KW();
        $encrypted_cek = $pbes2->wrapKey($key, $cek, $header, $header);
        static::assertTrue(isset($header['p2s']));
        static::assertEquals(4096, $header['p2c']);
        static::assertEquals($cek, $pbes2->unwrapKey($key, $encrypted_cek, $header));
    }

    /**
     * @test
     */
    public function pBES2HS512A256KW(): void
    {
        $header = [
            'alg' => 'PBES2-HS512+A256KW',
            'enc' => 'A256CBC-HS512',
            'cty' => 'jwk+json',
        ];
        $key = new JWK([
            'kty' => 'oct',
            'k' => Base64Url::encode($this->convertArrayToBinString([84, 104, 117, 115, 32, 102, 114, 111, 109, 32, 109, 121, 32, 108, 105, 112, 115, 44, 32, 98, 121, 32, 121, 111, 117, 114, 115, 44, 32, 109, 121, 32, 115, 105, 110, 32, 105, 115, 32, 112, 117, 114, 103, 101, 100, 46])),
        ]);

        $cek = $this->convertArrayToBinString([111, 27, 25, 52, 66, 29, 20, 78, 92, 176, 56, 240, 65, 208, 82, 112, 161, 131, 36, 55, 202, 236, 185, 172, 129, 23, 153, 194, 195, 48, 253, 182]);

        $pbes2 = new PBES2HS512A256KW();
        $encrypted_cek = $pbes2->wrapKey($key, $cek, $header, $header);
        static::assertTrue(isset($header['p2s']));
        static::assertEquals(4096, $header['p2c']);
        static::assertEquals($cek, $pbes2->unwrapKey($key, $encrypted_cek, $header));
    }

    /**
     * @test
     */
    public function badKeyType(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Wrong key type.');
        $header = [
            'alg' => 'PBES2-HS512+A256KW',
            'enc' => 'A256CBC-HS512',
            'cty' => 'jwk+json',
        ];
        $key = new JWK([
            'kty' => 'dir',
            'dir' => Base64Url::encode($this->convertArrayToBinString([84, 104, 117, 115, 32, 102, 114, 111, 109, 32, 109, 121, 32, 108, 105, 112, 115, 44, 32, 98, 121, 32, 121, 111, 117, 114, 115, 44, 32, 109, 121, 32, 115, 105, 110, 32, 105, 115, 32, 112, 117, 114, 103, 101, 100, 46])),
        ]);

        $cek = $this->convertArrayToBinString([111, 27, 25, 52, 66, 29, 20, 78, 92, 176, 56, 240, 65, 208, 82, 112, 161, 131, 36, 55, 202, 236, 185, 172, 129, 23, 153, 194, 195, 48, 253, 182]);

        $pbes2 = new PBES2HS512A256KW();
        $pbes2->wrapKey($key, $cek, $header, $header);
    }

    /**
     * @test
     */
    public function invalidKeyType(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The key parameter "k" is missing.');
        $header = [
            'alg' => 'PBES2-HS512+A256KW',
            'enc' => 'A256CBC-HS512',
            'cty' => 'jwk+json',
        ];
        $key = new JWK([
            'kty' => 'oct',
            'dir' => Base64Url::encode($this->convertArrayToBinString([84, 104, 117, 115, 32, 102, 114, 111, 109, 32, 109, 121, 32, 108, 105, 112, 115, 44, 32, 98, 121, 32, 121, 111, 117, 114, 115, 44, 32, 109, 121, 32, 115, 105, 110, 32, 105, 115, 32, 112, 117, 114, 103, 101, 100, 46])),
        ]);

        $cek = $this->convertArrayToBinString([111, 27, 25, 52, 66, 29, 20, 78, 92, 176, 56, 240, 65, 208, 82, 112, 161, 131, 36, 55, 202, 236, 185, 172, 129, 23, 153, 194, 195, 48, 253, 182]);

        $pbes2 = new PBES2HS512A256KW();
        $pbes2->wrapKey($key, $cek, $header, $header);
    }

    /**
     * @test
     */
    public function algorithmParameterIsMissing(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The header parameter "alg" is missing.');
        $header = [
            'enc' => 'A256CBC-HS512',
            'cty' => 'jwk+json',
        ];
        $key = new JWK([
            'kty' => 'oct',
            'k' => Base64Url::encode($this->convertArrayToBinString([84, 104, 117, 115, 32, 102, 114, 111, 109, 32, 109, 121, 32, 108, 105, 112, 115, 44, 32, 98, 121, 32, 121, 111, 117, 114, 115, 44, 32, 109, 121, 32, 115, 105, 110, 32, 105, 115, 32, 112, 117, 114, 103, 101, 100, 46])),
        ]);

        $cek = $this->convertArrayToBinString([111, 27, 25, 52, 66, 29, 20, 78, 92, 176, 56, 240, 65, 208, 82, 112, 161, 131, 36, 55, 202, 236, 185, 172, 129, 23, 153, 194, 195, 48, 253, 182]);

        $pbes2 = new PBES2HS512A256KW();
        $pbes2->wrapKey($key, $cek, $header, $header);
    }

    /**
     * @test
     */
    public function p2CParameterIsMissing(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The header parameter "p2s" is missing.');
        $header = [
            'alg' => 'PBES2-HS256+A128KW',
            'p2c' => 4096,
            'enc' => 'A128CBC-HS256',
            'cty' => 'jwk+json',
        ];
        $key = new JWK([
            'kty' => 'oct',
            'k' => Base64Url::encode($this->convertArrayToBinString([84, 104, 117, 115, 32, 102, 114, 111, 109, 32, 109, 121, 32, 108, 105, 112, 115, 44, 32, 98, 121, 32, 121, 111, 117, 114, 115, 44, 32, 109, 121, 32, 115, 105, 110, 32, 105, 115, 32, 112, 117, 114, 103, 101, 100, 46])),
        ]);

        $pbes2 = new PBES2HS256A128KW();

        $wrapped_cek = Base64Url::decode('TrqXOwuNUfDV9VPTNbyGvEJ9JMjefAVn-TR1uIxR9p6hsRQh9Tk7BA');

        $pbes2->unwrapKey($key, $wrapped_cek, $header);
    }

    /**
     * @test
     */
    public function p2SParameterIsMissing(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The header parameter "p2c" is missing.');
        $header = [
            'alg' => 'PBES2-HS256+A128KW',
            'p2s' => '2WCTcJZ1Rvd_CJuJripQ1w',
            'enc' => 'A128CBC-HS256',
            'cty' => 'jwk+json',
        ];
        $key = new JWK([
            'kty' => 'oct',
            'k' => Base64Url::encode($this->convertArrayToBinString([84, 104, 117, 115, 32, 102, 114, 111, 109, 32, 109, 121, 32, 108, 105, 112, 115, 44, 32, 98, 121, 32, 121, 111, 117, 114, 115, 44, 32, 109, 121, 32, 115, 105, 110, 32, 105, 115, 32, 112, 117, 114, 103, 101, 100, 46])),
        ]);

        $pbes2 = new PBES2HS256A128KW();

        $wrapped_cek = Base64Url::decode('TrqXOwuNUfDV9VPTNbyGvEJ9JMjefAVn-TR1uIxR9p6hsRQh9Tk7BA');

        $pbes2->unwrapKey($key, $wrapped_cek, $header);
    }

    /**
     * @return string
     */
    private function convertArrayToBinString(array $data)
    {
        foreach ($data as $key => $value) {
            $data[$key] = str_pad(dechex($value), 2, '0', STR_PAD_LEFT);
        }

        return hex2bin(implode('', $data));
    }
}
