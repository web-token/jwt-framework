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

namespace Jose\Component\Signature\Algorithm\Signature;

use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\HS1;
use Jose\Component\Signature\Algorithm\HS256_64;
use PHPUnit\Framework\TestCase;

/**
 * @group Unit
 * @group NewAlgorithm
 */
class HMACSignatureTest extends TestCase
{
    public function testHS1SignAndVerify()
    {
        $key = $this->getKey();
        $hmac = new HS1();
        $data = 'Live long and Prosper.';

        self::assertEquals('HS1', $hmac->name());

        $signature = $hmac->sign($key, $data);

        self::assertTrue($hmac->verify($key, $data, $signature));
    }

    public function testHS256SignAndVerify()
    {
        $key = $this->getKey();
        $hmac = new HS256_64();
        $data = 'Live long and Prosper.';

        self::assertEquals('HS256/64', $hmac->name());

        $signature = $hmac->sign($key, $data);

        self::assertEquals(hex2bin('89f750759cb8ad93'), $signature);
        self::assertTrue($hmac->verify($key, $data, $signature));
    }

    private function getKey(): JWK
    {
        return JWK::create([
            'kty' => 'oct',
            'k'   => 'foo',
        ]);
    }
}
