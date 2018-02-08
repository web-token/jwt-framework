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

namespace Jose\Component\Core\Tests;

use Jose\Component\Core\JWK;
use PHPUnit\Framework\TestCase;

/**
 * @group Unit
 * @group JWK
 */
class JWKTest extends TestCase
{
    /**
     * @test
     */
    public function aKeyContainsAllExpectedParameters()
    {
        $jwk = JWK::create([
            'kty'     => 'EC',
            'crv'     => 'P-256',
            'x'       => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y'       => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'use'     => 'sig',
            'key_ops' => ['sign'],
            'alg'     => 'ES256',
            'bar'     => 'plic',
        ]);

        self::assertEquals('EC', $jwk->get('kty'));
        self::assertEquals('ES256', $jwk->get('alg'));
        self::assertEquals('sig', $jwk->get('use'));
        self::assertFalse($jwk->has('kid'));
        self::assertEquals(['sign'], $jwk->get('key_ops'));
        self::assertEquals('P-256', $jwk->get('crv'));
        self::assertFalse($jwk->has('x5u'));
        self::assertFalse($jwk->has('x5c'));
        self::assertFalse($jwk->has('x5t'));
        self::assertFalse($jwk->has('x5t#256'));
        self::assertEquals('f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU', $jwk->get('x'));
        self::assertEquals('x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0', $jwk->get('y'));
        self::assertEquals('{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","use":"sig","key_ops":["sign"],"alg":"ES256","bar":"plic"}', json_encode($jwk));
        self::assertEquals('oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U', $jwk->thumbprint('sha256'));
        self::assertEquals('EMMMl6Rj75mqhcABihxxl_VCN9s', $jwk->thumbprint('sha1'));
        self::assertEquals('dqwHnan4iJ1_eEll-o4Egw', $jwk->thumbprint('md5'));
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The hash algorithm "foo" is not supported.
     */
    public function iCannotGetTheThumbprintOfTheKeyWhenIUseAnUnsupportedHashingAlgorithm()
    {
        $jwk = JWK::create([
            'kty'     => 'EC',
            'crv'     => 'P-256',
            'x'       => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y'       => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'use'     => 'sig',
            'key_ops' => ['sign'],
            'alg'     => 'ES256',
            'bar'     => 'plic',
        ]);

        $jwk->thumbprint('foo');
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The parameter "kty" is mandatory.
     */
    public function iMustSetAtLeastTheKtyParameter()
    {
        JWK::create([]);
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The value identified by "ABCD" does not exist.
     */
    public function iCannotGetAParameterThatDoesNotExist()
    {
        $jwk = JWK::create([
            'kty'     => 'EC',
            'crv'     => 'P-256',
            'x'       => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y'       => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'use'     => 'sign',
            'key_ops' => ['sign'],
            'alg'     => 'ES256',
            'bar'     => 'plic',
        ]);

        $jwk->get('ABCD');
    }

    /**
     * @test
     */
    public function iCanConvertAPrivateKeyIntoPublicKey()
    {
        $private = JWK::create([
            'kty'     => 'EC',
            'crv'     => 'P-256',
            'x'       => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y'       => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'd'       => 'jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI',
            'use'     => 'sign',
            'key_ops' => ['verify'],
            'alg'     => 'ES256',
            'kid'     => '9876543210',
        ]);

        $public = $private->toPublic();

        self::assertEquals(json_encode([
            'kty'     => 'EC',
            'crv'     => 'P-256',
            'x'       => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y'       => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'use'     => 'sign',
            'key_ops' => ['verify'],
            'alg'     => 'ES256',
            'kid'     => '9876543210',
        ]), json_encode($public));
    }
}
