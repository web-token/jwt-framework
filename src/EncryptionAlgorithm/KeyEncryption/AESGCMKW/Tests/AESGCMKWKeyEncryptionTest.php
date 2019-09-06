<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2019 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Encryption\Algorithm\KeyEncryption\Tests;

use Base64Url\Base64Url;
use Jose\Component\Core\JWK;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A128GCMKW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A192GCMKW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A256GCMKW;
use PHPUnit\Framework\TestCase;

/**
 * @group AESGCMKW
 * @group unit
 *
 * @internal
 */
class AESGCMKWKeyEncryptionTest extends TestCase
{
    /**
     * @test
     */
    public function a128GCMKW()
    {
        $header = [];
        $key = new JWK([
            'kty' => 'oct',
            'k' => Base64Url::encode(hex2bin('000102030405060708090A0B0C0D0E0F')),
        ]);

        $cek = hex2bin('00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F');

        $aeskw = new A128GCMKW();

        $wrapped_cek = $aeskw->wrapKey($key, $cek, $header, $header);

        static::assertTrue(\array_key_exists('iv', $header));
        static::assertTrue(\array_key_exists('tag', $header));
        static::assertNotNull($header['iv']);
        static::assertNotNull($header['tag']);
        static::assertEquals($cek, $aeskw->unwrapKey($key, $wrapped_cek, $header));
    }

    /**
     * @test
     */
    public function badKey()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Wrong key type.');

        $header = [];
        $key = new JWK([
            'kty' => 'EC',
        ]);

        $cek = hex2bin('00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F');

        $aeskw = new A128GCMKW();

        $aeskw->wrapKey($key, $cek, $header, $header);
    }

    /**
     * @test
     */
    public function missingParameters()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Parameter "iv" is missing.');

        $header = [];
        $key = new JWK([
            'kty' => 'oct',
            'k' => Base64Url::encode(hex2bin('000102030405060708090A0B0C0D0E0F')),
        ]);

        $cek = hex2bin('00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F');

        $aeskw = new A128GCMKW();

        $aeskw->unwrapKey($key, $cek, $header);
    }

    /**
     * @test
     */
    public function a192GCMKW()
    {
        $header = [];
        $key = new JWK([
            'kty' => 'oct',
            'k' => Base64Url::encode(hex2bin('000102030405060708090A0B0C0D0E0F1011121314151617')),
        ]);

        $cek = hex2bin('00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F');

        $aeskw = new A192GCMKW();

        $wrapped_cek = $aeskw->wrapKey($key, $cek, $header, $header);

        static::assertTrue(\array_key_exists('iv', $header));
        static::assertTrue(\array_key_exists('tag', $header));
        static::assertNotNull($header['iv']);
        static::assertNotNull($header['tag']);
        static::assertEquals($cek, $aeskw->unwrapKey($key, $wrapped_cek, $header));
    }

    /**
     * @test
     */
    public function a256GCMKW()
    {
        $header = [];
        $key = new JWK([
            'kty' => 'oct',
            'k' => Base64Url::encode(hex2bin('000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F')),
        ]);

        $cek = hex2bin('00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F');

        $aeskw = new A256GCMKW();

        $wrapped_cek = $aeskw->wrapKey($key, $cek, $header, $header);

        static::assertTrue(\array_key_exists('iv', $header));
        static::assertTrue(\array_key_exists('tag', $header));
        static::assertNotNull($header['iv']);
        static::assertNotNull($header['tag']);
        static::assertEquals($cek, $aeskw->unwrapKey($key, $wrapped_cek, $header));
    }
}
