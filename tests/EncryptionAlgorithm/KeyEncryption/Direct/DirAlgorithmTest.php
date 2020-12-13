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
use Jose\Component\Encryption\Algorithm\KeyEncryption\Dir;
use PHPUnit\Framework\TestCase;

/**
 * Class DirAlgorithmTest.
 *
 * @group unit
 *
 * @internal
 */
class DirAlgorithmTest extends TestCase
{
    /**
     * @covers \Jose\Component\Encryption\Algorithm\KeyEncryption\Dir
     * @test
     */
    public function invalidKey(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Wrong key type.');

        $key = new JWK([
            'kty' => 'EC',
        ]);

        $dir = new Dir();

        $dir->getCEK($key);
    }

    /**
     * @covers \Jose\Component\Encryption\Algorithm\KeyEncryption\Dir
     * @test
     */
    public function validCEK(): void
    {
        $key = new JWK([
            'kty' => 'oct',
            'k' => Base64Url::encode('ABCD'),
        ]);

        $dir = new Dir();

        static::assertEquals('ABCD', $dir->getCEK($key));
    }
}
