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

use Base64Url\Base64Url;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\ES384;
use Jose\Component\Signature\Algorithm\ES512;
use PHPUnit\Framework\TestCase;

/**
 * @group ECDSA
 * @group Unit
 */
class ECDSASignatureTest extends TestCase
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
            'kty' => 'RSA',
        ]);

        $ecdsa = new ES256();
        $data = 'Live long and Prosper.';

        $ecdsa->sign($key, $data);
    }

    /**
     * @test
     */
    public function eS256Verify()
    {
        $key = new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'd' => 'jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI',
        ]);

        $ecdsa = new ES256();
        $data = 'eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ';
        $signature = 'DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q';

        $sign = $ecdsa->sign($key, $data);

        static::assertTrue($ecdsa->verify($key, $data, $sign));
        static::assertTrue($ecdsa->verify($key, $data, Base64Url::decode($signature)));
    }

    /**
     * @test
     */
    public function eS256SignVerify()
    {
        $key = new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'd' => 'jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI',
        ]);

        $ecdsa = new ES256();

        $data = 'eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ';
        $signature = $ecdsa->sign($key, $data);

        static::assertTrue($ecdsa->verify($key, $data, $signature));
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The EC key is not private
     *
     * @test
     */
    public function keyNotPrivate()
    {
        $key = new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
        ]);

        $ecdsa = new ES256();

        $data = 'eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ';
        $ecdsa->sign($key, $data);
    }

    /**
     * @test
     */
    public function hS384SignVerify()
    {
        $key = new JWK([
            'kty' => 'EC',
            'crv' => 'P-384',
            'd' => 'pcSSXrbeZEOaBIs7IwqcU9M_OOM81XhZuOHoGgmS_2PdECwcdQcXzv7W8-lYL0cr',
            'x' => '6f-XZsg2Tvn0EoEapQ-ylMYNtsm8CPf0cb8HI2EkfY9Bqpt3QMzwlM7mVsFRmaMZ',
            'y' => 'b8nOnRwmpmEnvA2U8ydS-dbnPv7bwYl-q1qNeh8Wpjor3VO-RTt4ce0Pn25oGGWU',
        ]);

        $ecdsa = new ES384();

        $data = 'eyJhbGciOiJFUzUxMiJ9.UGF5bG9hZA';
        $signature = $ecdsa->sign($key, $data);

        static::assertTrue($ecdsa->verify($key, $data, $signature));
    }

    /**
     * @test
     */
    public function hS512Verify()
    {
        $key = new JWK([
            'kty' => 'EC',
            'crv' => 'P-521',
            'x' => 'AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk',
            'y' => 'ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2',
            'd' => 'AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPAxerEzgdRhajnu0ferB0d53vM9mE15j2C',
        ]);

        $ecdsa = new ES512();
        $data = 'eyJhbGciOiJFUzUxMiJ9.UGF5bG9hZA';
        $signature = 'AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZqwqT2SI-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8KpEHwJjyqOgzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn';

        $sign = $ecdsa->sign($key, $data);

        static::assertTrue($ecdsa->verify($key, $data, $sign));
        static::assertTrue($ecdsa->verify($key, $data, Base64Url::decode($signature)));
    }

    /**
     * @test
     */
    public function hS512SignVerify()
    {
        $key = new JWK([
            'kty' => 'EC',
            'crv' => 'P-521',
            'x' => 'AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk',
            'y' => 'ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2',
            'd' => 'AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPAxerEzgdRhajnu0ferB0d53vM9mE15j2C',
        ]);

        $ecdsa = new ES512();

        $data = 'eyJhbGciOiJFUzUxMiJ9.UGF5bG9hZA';
        $signature = $ecdsa->sign($key, $data);

        static::assertTrue($ecdsa->verify($key, $data, $signature));
    }

    /**
     * @test
     */
    public function badSignature()
    {
        $key = new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
        ]);

        $ecdsa = new ES256();

        $data = 'eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ';
        $signature = 'DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3';

        static::assertFalse($ecdsa->verify($key, $data, Base64Url::decode($signature)));
    }
}
