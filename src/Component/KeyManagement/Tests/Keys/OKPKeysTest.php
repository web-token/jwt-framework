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

namespace Jose\Component\KeyManagement\Tests\Keys;

use InvalidArgumentException;
use Jose\Component\KeyManagement\JWKFactory;
use PHPUnit\Framework\TestCase;

/**
 * @group OKPKeys
 * @group unit
 *
 * @internal
 */
class OKPKeysTest extends TestCase
{
    /**
     * @test
     */
    public function createOKPKeyWithInvalidKeySize(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Unsupported "Ed455" curve');

        JWKFactory::createOKPKey('Ed455');
    }

    /**
     * @test
     */
    public function createOKPKeyWithCurveX25519(): void
    {
        $jwk = JWKFactory::createOKPKey(
            'X25519',
            [
                'kid' => 'KEY',
                'alg' => 'ECDH-ES',
                'use' => 'enc',
            ]
        );

        static::assertEquals('OKP', $jwk->get('kty'));
        static::assertTrue($jwk->has('x'));
        static::assertTrue($jwk->has('d'));
        static::assertEquals('KEY', $jwk->get('kid'));
        static::assertEquals('ECDH-ES', $jwk->get('alg'));
        static::assertEquals('enc', $jwk->get('use'));
    }

    /**
     * @test
     */
    public function createOKPKeyWithCurveEd25519(): void
    {
        $jwk = JWKFactory::createOKPKey(
            'Ed25519',
            [
                'kid' => 'KEY',
                'alg' => 'EdDSA',
                'use' => 'sig',
            ]
        );

        static::assertEquals('OKP', $jwk->get('kty'));
        static::assertTrue($jwk->has('x'));
        static::assertTrue($jwk->has('d'));
        static::assertEquals('KEY', $jwk->get('kid'));
        static::assertEquals('EdDSA', $jwk->get('alg'));
        static::assertEquals('sig', $jwk->get('use'));
    }
}
