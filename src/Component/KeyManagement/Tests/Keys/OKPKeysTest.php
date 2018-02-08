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

namespace Jose\Component\KeyManagement\Tests\Keys;

use Jose\Component\KeyManagement\JWKFactory;
use PHPUnit\Framework\TestCase;

/**
 * @group OKPKeys
 * @group Unit
 */
class OKPKeysTest extends TestCase
{
    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Unsupported "Ed455" curve
     */
    public function testCreateOKPKeyWithInvalidKeySize()
    {
        JWKFactory::createOKPKey('Ed455');
    }

    public function testCreateOKPKeyWithCurveX25519()
    {
        $jwk = JWKFactory::createOKPKey(
            'X25519',
            [
                'kid' => 'KEY',
                'alg' => 'ECDH-ES',
                'use' => 'enc',
            ]
        );

        self::assertEquals('OKP', $jwk->get('kty'));
        self::assertTrue($jwk->has('x'));
        self::assertTrue($jwk->has('d'));
        self::assertEquals('KEY', $jwk->get('kid'));
        self::assertEquals('ECDH-ES', $jwk->get('alg'));
        self::assertEquals('enc', $jwk->get('use'));
    }

    public function testCreateOKPKeyWithCurveEd25519()
    {
        $jwk = JWKFactory::createOKPKey(
            'Ed25519',
            [
                'kid' => 'KEY',
                'alg' => 'EdDSA',
                'use' => 'sig',
            ]
        );

        self::assertEquals('OKP', $jwk->get('kty'));
        self::assertTrue($jwk->has('x'));
        self::assertTrue($jwk->has('d'));
        self::assertEquals('KEY', $jwk->get('kid'));
        self::assertEquals('EdDSA', $jwk->get('alg'));
        self::assertEquals('sig', $jwk->get('use'));
    }
}
