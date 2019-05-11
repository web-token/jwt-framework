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
use Jose\Component\Encryption\Algorithm\KeyEncryption\Dir;
use PHPUnit\Framework\TestCase;

/**
 * Class DirAlgorithmTest.
 *
 * @group unit
 *
 * @internal
 * @coversNothing
 */
class DirAlgorithmTest extends TestCase
{
    /**
     * @test
     */
    public function invalidKey()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Wrong key type.');

        $key = new JWK([
            'kty' => 'EC',
        ]);

        $dir = new Dir();

        $dir->getCEK($key);
    }

    /**
     * @test
     */
    public function validCEK()
    {
        $key = new JWK([
            'kty' => 'oct',
            'k' => Base64Url::encode('ABCD'),
        ]);

        $dir = new Dir();

        static::assertEquals('ABCD', $dir->getCEK($key));
    }
}
