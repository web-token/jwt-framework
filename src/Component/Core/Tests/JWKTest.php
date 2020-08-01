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

namespace Jose\Component\Core\Tests;

use InvalidArgumentException;
use Jose\Component\Core\JWK;
use PHPUnit\Framework\TestCase;

/**
 * @group unit
 * @group JWK
 *
 * @internal
 */
class JWKTest extends TestCase
{
    /**
     * @test
     */
    public function aKeyContainsAllExpectedParameters(): void
    {
        $jwk = new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'use' => 'sig',
            'key_ops' => ['sign'],
            'alg' => 'ES256',
            'bar' => 'plic',
        ]);

        static::assertEquals('EC', $jwk->get('kty'));
        static::assertEquals('ES256', $jwk->get('alg'));
        static::assertEquals('sig', $jwk->get('use'));
        static::assertFalse($jwk->has('kid'));
        static::assertEquals(['sign'], $jwk->get('key_ops'));
        static::assertEquals('P-256', $jwk->get('crv'));
        static::assertFalse($jwk->has('x5u'));
        static::assertFalse($jwk->has('x5c'));
        static::assertFalse($jwk->has('x5t'));
        static::assertFalse($jwk->has('x5t#256'));
        static::assertEquals('f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU', $jwk->get('x'));
        static::assertEquals('x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0', $jwk->get('y'));
        static::assertEquals('{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","use":"sig","key_ops":["sign"],"alg":"ES256","bar":"plic"}', json_encode($jwk));
        static::assertEquals('oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U', $jwk->thumbprint('sha256'));
        static::assertEquals('EMMMl6Rj75mqhcABihxxl_VCN9s', $jwk->thumbprint('sha1'));
        static::assertEquals('dqwHnan4iJ1_eEll-o4Egw', $jwk->thumbprint('md5'));
    }

    /**
     * @test
     */
    public function iCannotGetTheThumbprintOfTheKeyWhenIUseAnUnsupportedHashingAlgorithm(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The hash algorithm "foo" is not supported.');

        $jwk = new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'use' => 'sig',
            'key_ops' => ['sign'],
            'alg' => 'ES256',
            'bar' => 'plic',
        ]);

        $jwk->thumbprint('foo');
    }

    /**
     * @test
     */
    public function iMustSetAtLeastTheKtyParameter(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The parameter "kty" is mandatory.');

        new JWK([]);
    }

    /**
     * @test
     */
    public function iCannotGetAParameterThatDoesNotExist(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The value identified by "ABCD" does not exist.');

        $jwk = new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'use' => 'sign',
            'key_ops' => ['sign'],
            'alg' => 'ES256',
            'bar' => 'plic',
        ]);

        $jwk->get('ABCD');
    }

    /**
     * @test
     */
    public function iCanConvertAPrivateKeyIntoPublicKey(): void
    {
        $private = new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'd' => 'jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI',
            'use' => 'sign',
            'key_ops' => ['verify'],
            'alg' => 'ES256',
            'kid' => '9876543210',
        ]);

        $public = $private->toPublic();

        static::assertEquals(json_encode([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'use' => 'sign',
            'key_ops' => ['verify'],
            'alg' => 'ES256',
            'kid' => '9876543210',
        ]), json_encode($public));
    }
}
