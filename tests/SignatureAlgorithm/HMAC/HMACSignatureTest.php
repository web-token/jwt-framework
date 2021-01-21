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

namespace Jose\Tests\Component\Signature\Algorithm;

use InvalidArgumentException;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\Algorithm\HS384;
use Jose\Component\Signature\Algorithm\HS512;
use PHPUnit\Framework\TestCase;

/**
 * @group HMAC
 * @group unit
 *
 * @internal
 */
class HMACSignatureTest extends TestCase
{
    /**
     * @test
     */
    public function invalidKey(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Wrong key type.');
        $key = new JWK([
            'kty' => 'EC',
        ]);

        $hmac = new HS256();
        $data = 'Live long and Prosper.';

        $hmac->hash($key, $data);
    }

    /**
     * @test
     */
    public function signatureHasBadBadLength(): void
    {
        $key = new JWK([
            'kty' => 'oct',
            'k' => 'foofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoo',
        ]);
        $hmac = new HS256();
        $data = 'Live long and Prosper.';

        static::assertFalse($hmac->verify($key, $data, hex2bin('326eb338c465d3587f3349df0b96ba81')));
    }

    /**
     * @test
     */
    public function hS256SignAndVerify(): void
    {
        $key = new JWK([
            'kty' => 'oct',
            'k' => 'foofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoo',
        ]);
        $hmac = new HS256();
        $data = 'Live long and Prosper.';

        $signature = $hmac->hash($key, $data);

        static::assertEquals(hex2bin('7ed268ef179f530a4a1c56225c352a6782cf5379085c484b4f355b6744d6f19d'), $signature);
        static::assertTrue($hmac->verify($key, $data, $signature));
    }

    /**
     * @test
     */
    public function hS384SignAndVerify(): void
    {
        $key = new JWK([
            'kty' => 'oct',
            'k' => 'foofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoo',
        ]);
        $hmac = new HS384();
        $data = 'Live long and Prosper.';

        $signature = $hmac->hash($key, $data);

        static::assertEquals(hex2bin('903ce2ef2878090d6117f88210d5a822d260fae66760186cb3326770748b9fa47c2d4531a4d5d868f99bcf7ea45c1ab4'), $signature);
        static::assertTrue($hmac->verify($key, $data, $signature));
    }

    /**
     * @test
     */
    public function hS512SignAndVerify(): void
    {
        $key = new JWK([
            'kty' => 'oct',
            'k' => 'foofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoo',
        ]);
        $hmac = new HS512();
        $data = 'Live long and Prosper.';

        $signature = $hmac->hash($key, $data);

        static::assertEquals(hex2bin('e8b36712b6c6dc422eec77f31ce372ccac769450413238158bd702069630456a148d0c10dd3a661a774217fb90b0d5f94fa6c3c985438bade92ff975b9e4dc04'), $signature);
        static::assertTrue($hmac->verify($key, $data, $signature));
    }
}
