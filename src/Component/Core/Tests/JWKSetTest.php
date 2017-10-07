<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Core\Tests;

use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use PHPUnit\Framework\TestCase;

/**
 * final class JWKTest.
 *
 * @group Unit
 * @group JWKSet
 */
final class JWKSetTest extends TestCase
{
    public function testKeySelection()
    {
        $jwkset = $this->getPublicKeySet();

        $jwk = $jwkset->selectKey('enc');
        self::assertInstanceOf(JWK::class, $jwk);
    }

    public function testKeySelectionWithAlgorithm()
    {
        $jwkset = $this->getPublicKeySet();

        $jwk = $jwkset->selectKey('enc', new FooAlgorithm());
        self::assertInstanceOf(JWK::class, $jwk);
        self::assertEquals([
                'kid' => '71ee230371d19630bc17fb90ccf20ae632ad8cf8',
                'kty' => 'FOO',
                'alg' => 'foo',
                'use' => 'enc',
            ],
            $jwk->all()
        );
    }

    public function testKeySelectionWithAlgorithmAndKeyId()
    {
        $jwkset = $this->getPublicKeySet();

        $jwk = $jwkset->selectKey('sig', new FooAlgorithm(), ['kid' => '02491f945c951adf156f370788e8ccdabf8877a8']);
        self::assertInstanceOf(JWK::class, $jwk);
        self::assertEquals([
                'kid' => '02491f945c951adf156f370788e8ccdabf8877a8',
                'kty' => 'FOO',
                'alg' => 'foo',
                'use' => 'sig',
            ],
            $jwk->all()
        );
    }

    public function testKeySelectionWithKeyId()
    {
        $jwkset = $this->getPublicKeySet();

        $jwk = $jwkset->selectKey('sig', null, ['kid' => '02491f945c951adf156f370788e8ccdabf8877a8']);
        self::assertInstanceOf(JWK::class, $jwk);
        self::assertEquals([
                'kid' => '02491f945c951adf156f370788e8ccdabf8877a8',
                'kty' => 'FOO',
                'alg' => 'foo',
                'use' => 'sig',
            ],
            $jwk->all()
        );
    }

    public function testKeySelectionReturnsNothing()
    {
        $jwkset = $this->getPublicKeySet();

        $jwk = $jwkset->selectKey('enc', null, ['kid' => '02491f945c951adf156f370788e8ccdabf8877a8']);
        self::assertNull($jwk);
    }

    public function testCreateKeySetFromValues()
    {
        $values = ['keys' => [[
            'kid' => '71ee230371d19630bc17fb90ccf20ae632ad8cf8',
            'kty' => 'FOO',
            'alg' => 'foo',
            'use' => 'sig',
        ]]];
        $jwkset = JWKSet::createFromKeyData($values);
        self::assertInstanceOf(JWKSet::class, $jwkset);
        self::assertEquals(1, count($jwkset));
        self::assertTrue($jwkset->has('71ee230371d19630bc17fb90ccf20ae632ad8cf8'));
        self::assertFalse($jwkset->has(0));
    }

    /**
     * @return JWKSet
     */
    private function getPublicKeySet(): JWKSet
    {
        $keys = ['keys' => [
            [
                'kid' => '71ee230371d19630bc17fb90ccf20ae632ad8cf8',
                'kty' => 'FOO',
                'alg' => 'foo',
                'use' => 'enc',
            ],
            [
                'kid' => '02491f945c951adf156f370788e8ccdabf8877a8',
                'kty' => 'FOO',
                'alg' => 'foo',
                'use' => 'sig',
            ],
            [
                'kty' => 'EC',
                'crv' => 'P-256',
                'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
                'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            ],
        ]];

        return JWKSet::createFromKeyData($keys);
    }
}
