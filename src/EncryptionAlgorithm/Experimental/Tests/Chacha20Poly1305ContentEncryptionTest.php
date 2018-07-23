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

namespace Jose\Component\Encryption\Algorithm\Tests;

use Jose\Component\Core\JWK;
use Jose\Component\Encryption\Algorithm\KeyEncryption\Chacha20Poly1305;
use PHPUnit\Framework\TestCase;

/**
 * @group Unit
 * @group NewAlgorithm
 */
class Chacha20Poly1305ContentEncryptionTest extends TestCase
{
    /**
     * {@inheritdoc}
     */
    protected function setUp()
    {
        if (!\in_array('chacha20-poly1305', \openssl_get_cipher_methods(), true)) {
            $this->markTestSkipped('The algorithm "chacha20-poly1305" is not supported in this platform.');
        }
    }

    public function testContentEncryptionAndDecryption()
    {
        $header = [];
        $algorithm = new Chacha20Poly1305();
        $cek = \random_bytes(256 / 8);
        $jwk = $this->getKey();

        $additionalHeader = [];
        $encrypted = $algorithm->encryptKey($jwk, $cek, $header, $additionalHeader);
        $decrypted = $algorithm->decryptKey($jwk, $encrypted, $additionalHeader);

        self::assertEquals($cek, $decrypted);
    }

    private function getKey(): JWK
    {
        return JWK::create([
            'kty' => 'oct',
            'k' => 'oahUIoWw0K0usKNuOR6H4wkf4oBUXHTxRvgb48E-BVvxkeDNjbC4he8rUWcJoZmds2h7M70imEVhRU5djINXtqllXI4DFqcI1DgjT9LewND8MW2Krf3Spsk_ZkoFnilakGygTwpZ3uesH-PFABNIUYpOiN15dsQRkgr0vEhxN92i2asbOenSZeyaxziK72UwxrrKoExv6kc5twXTq4h-QChLOln0_mtUZwfsRaMStPs6mS6XrgxnxbWhojf663tuEQueGC-FCMfra36C9knDFGzKsNa7LZK2djYgyD3JR_MB_4NUJW_TqOQtwHYbxevoJArm-L5StowjzGy-_bq6Gw',
        ]);
    }
}
