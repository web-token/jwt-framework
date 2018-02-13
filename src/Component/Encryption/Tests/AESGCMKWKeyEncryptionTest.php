<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Encryption\Tests;

use Base64Url\Base64Url;
use Jose\Component\Core\JWK;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A128GCMKW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A192GCMKW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A256GCMKW;

/**
 * @group AESGCMKW
 * @group Unit
 */
final class AESGCMKWKeyEncryptionTest extends EncryptionTest
{
    public function testA128GCMKW()
    {
        $header = [];
        $key = JWK::create([
            'kty' => 'oct',
            'k'   => Base64Url::encode(hex2bin('000102030405060708090A0B0C0D0E0F')),
        ]);

        $cek = hex2bin('00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F');

        $aeskw = new A128GCMKW();

        $wrapped_cek = $aeskw->wrapKey($key, $cek, $header, $header);

        self::assertTrue(array_key_exists('iv', $header));
        self::assertTrue(array_key_exists('tag', $header));
        self::assertNotNull($header['iv']);
        self::assertNotNull($header['tag']);
        self::assertEquals($cek, $aeskw->unwrapKey($key, $wrapped_cek, $header));
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Wrong key type.
     */
    public function testBadKey()
    {
        $header = [];
        $key = JWK::create([
            'kty' => 'EC',
        ]);

        $cek = hex2bin('00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F');

        $aeskw = new A128GCMKW();

        $aeskw->wrapKey($key, $cek, $header, $header);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Parameter "iv" is missing.
     */
    public function testMissingParameters()
    {
        $header = [];
        $key = JWK::create([
            'kty' => 'oct',
            'k'   => Base64Url::encode(hex2bin('000102030405060708090A0B0C0D0E0F')),
        ]);

        $cek = hex2bin('00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F');

        $aeskw = new A128GCMKW();

        $aeskw->unwrapKey($key, $cek, $header);
    }

    public function testA192GCMKW()
    {
        $header = [];
        $key = JWK::create([
            'kty' => 'oct',
            'k'   => Base64Url::encode(hex2bin('000102030405060708090A0B0C0D0E0F1011121314151617')),
        ]);

        $cek = hex2bin('00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F');

        $aeskw = new A192GCMKW();

        $wrapped_cek = $aeskw->wrapKey($key, $cek, $header, $header);

        self::assertTrue(array_key_exists('iv', $header));
        self::assertTrue(array_key_exists('tag', $header));
        self::assertNotNull($header['iv']);
        self::assertNotNull($header['tag']);
        self::assertEquals($cek, $aeskw->unwrapKey($key, $wrapped_cek, $header));
    }

    public function testA256GCMKW()
    {
        $header = [];
        $key = JWK::create([
            'kty' => 'oct',
            'k'   => Base64Url::encode(hex2bin('000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F')),
        ]);

        $cek = hex2bin('00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F');

        $aeskw = new A256GCMKW();

        $wrapped_cek = $aeskw->wrapKey($key, $cek, $header, $header);

        self::assertTrue(array_key_exists('iv', $header));
        self::assertTrue(array_key_exists('tag', $header));
        self::assertNotNull($header['iv']);
        self::assertNotNull($header['tag']);
        self::assertEquals($cek, $aeskw->unwrapKey($key, $wrapped_cek, $header));
    }
}
