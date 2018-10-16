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

use Base64Url\Base64Url;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A128CCM_16_128;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A128CCM_16_64;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A128CCM_64_128;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A128CCM_64_64;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A256CCM_16_128;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A256CCM_16_64;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A256CCM_64_128;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A256CCM_64_64;
use Jose\Component\Encryption\Algorithm\ContentEncryption\AESCCM;
use PHPUnit\Framework\TestCase;

/**
 * @group Unit
 * @group NewAlgorithm
 */
class AESCCMContentEncryptionTest extends TestCase
{
    /**
     * @dataProvider getAlgorithms
     *
     * @test
     */
    public function contentEncryptionAndDecryption(string $algorithmClass)
    {
        /** @var AESCCM $algorithm */
        $algorithm = new $algorithmClass();
        $header = Base64Url::encode(\json_encode(['alg' => 'ECDH-ES', 'enc' => $algorithm->name()]));
        $tag = null;
        $cek = \random_bytes($algorithm->getCEKSize() / 8);
        $iv = \random_bytes($algorithm->getIVSize());
        $plaintext = 'Live long and Prosper.';

        $cyphertext = $algorithm->encryptContent($plaintext, $cek, $iv, null, $header, $tag);

        static::assertNotNull($tag);
        static::assertEquals($plaintext, $algorithm->decryptContent($cyphertext, $cek, $iv, null, $header, $tag));
    }

    public function getAlgorithms(): array
    {
        return [
            [A128CCM_16_64::class],
            [A128CCM_16_128::class],
            [A128CCM_64_64::class],
            [A128CCM_64_128::class],
            [A256CCM_16_64::class],
            [A256CCM_16_128::class],
            [A256CCM_64_64::class],
            [A256CCM_64_128::class],
        ];
    }
}
