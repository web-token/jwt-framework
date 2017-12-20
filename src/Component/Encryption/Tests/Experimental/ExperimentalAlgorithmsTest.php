<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Encryption\Tests;

use Base64Url\Base64Url;
use Jose\Component\Core\JWK;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ChaCha20Poly1305IETF;
use const Sodium\CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES;

/**
 * @group LibSodium
 * @group Unit
 */
final class ExperimentalAlgorithmsTest extends EncryptionTest
{
    public function testChaCha20Poly1305IETF()
    {
        $header = [];
        $key = JWK::create([
            'kty' => 'oct',
            'k' => Base64Url::encode(random_bytes(CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES)),
        ]);

        $cek = sodium_hex2bin('00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F');

        $algorithm = new ChaCha20Poly1305IETF();

        $wrapped_cek = $algorithm->encryptKey($key, $cek, $header, $header);

        self::assertTrue(array_key_exists('nonce', $header));
        self::assertNotNull($header['nonce']);
        self::assertEquals($cek, $algorithm->decryptKey($key, $wrapped_cek, $header));
    }
}
