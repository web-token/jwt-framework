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

namespace Jose\Component\Signature\Algorithm\Tests;

use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\Algorithm\HS384;
use Jose\Component\Signature\Algorithm\HS512;
use PHPUnit\Framework\TestCase;

/**
 * @group HMAC
 * @group Unit
 */
class HMACSignatureTest extends TestCase
{
    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Wrong key type.
     *
     * @test
     */
    public function invalidKey()
    {
        $key = new JWK([
            'kty' => 'EC',
        ]);

        $hmac = new HS256();
        $data = 'Live long and Prosper.';

        $hmac->sign($key, $data);
    }

    /**
     * @test
     */
    public function signatureHasBadBadLength()
    {
        $key = new JWK([
            'kty' => 'oct',
            'k' => 'foo',
        ]);
        $hmac = new HS256();
        $data = 'Live long and Prosper.';

        static::assertFalse($hmac->verify($key, $data, \hex2bin('326eb338c465d3587f3349df0b96ba81')));
    }

    /**
     * @test
     */
    public function hS256SignAndVerify()
    {
        $key = new JWK([
            'kty' => 'oct',
            'k' => 'foo',
        ]);
        $hmac = new HS256();
        $data = 'Live long and Prosper.';

        $signature = $hmac->sign($key, $data);

        static::assertEquals(\hex2bin('89f750759cb8ad9315d7ec6bd8d5dc5899e0a97bc12f9e355f383776f53f025c'), $signature);
        static::assertTrue($hmac->verify($key, $data, $signature));
    }

    /**
     * @test
     */
    public function hS384SignAndVerify()
    {
        $key = new JWK([
            'kty' => 'oct',
            'k' => 'foo',
        ]);
        $hmac = new HS384();
        $data = 'Live long and Prosper.';

        $signature = $hmac->sign($key, $data);

        static::assertEquals(\hex2bin('8985f2c6efef1c1b9baf7d7b0b17ce6db65184044bdeaa01296fe6d61900224fc783f4bb7b7aadfdfb4d0663b1284e66'), $signature);
        static::assertTrue($hmac->verify($key, $data, $signature));
    }

    /**
     * @test
     */
    public function hS512SignAndVerify()
    {
        $key = new JWK([
            'kty' => 'oct',
            'k' => 'foo',
        ]);
        $hmac = new HS512();
        $data = 'Live long and Prosper.';

        $signature = $hmac->sign($key, $data);

        static::assertEquals(\hex2bin('6f91ca09dc2e655d089f1018fb447f16c68d65f32f54ea84542edb1db5dfbbda141cbb41741b7383a7dff6af56be564fd74a8857eab6a680094bbcb41b2f29e1'), $signature);
        static::assertTrue($hmac->verify($key, $data, $signature));
    }
}
