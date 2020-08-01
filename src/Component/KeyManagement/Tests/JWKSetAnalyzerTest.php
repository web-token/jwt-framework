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

namespace Jose\Component\KeyManagement\Tests;

use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\Analyzer;
use PHPUnit\Framework\TestCase;

/**
 * @group unit
 * @group JWKSetAnalyzer
 *
 * @internal
 */
class JWKSetAnalyzerTest extends TestCase
{
    /**
     * @var null|Analyzer\KeysetAnalyzerManager
     */
    private $keysetAnalyzerManager;

    /**
     * @test
     */
    public function theKeysetHasNoKey(): void
    {
        $jwkset = new JWKSet([]);
        $messages = $this->getKeysetAnalyzer()->analyze($jwkset);

        static::assertEmpty($messages);
    }

    /**
     * @test
     */
    public function theKeysetDoesNotMixesKeys(): void
    {
        $jwkset = new JWKSet([
            new JWK(['kty' => 'OKP']),
            new JWK(['kty' => 'OKP']),
            new JWK(['kty' => 'EC']),
            new JWK(['kty' => 'EC']),
        ]);
        $messages = $this->getKeysetAnalyzer()->analyze($jwkset);

        static::assertEmpty($messages);
    }

    /**
     * @test
     */
    public function theKeysetMixesKeys(): void
    {
        $jwkset = new JWKSet([
            new JWK(['kty' => 'oct']),
            new JWK(['kty' => 'OKP']),
            new JWK(['kty' => 'OKP']),
            new JWK(['kty' => 'EC']),
            new JWK(['kty' => 'EC']),
        ]);
        $messages = $this->getKeysetAnalyzer()->analyze($jwkset);

        static::assertNotEmpty($messages);
    }

    /**
     * @test
     */
    public function theKeysetHasOnlyPrivateKeys(): void
    {
        $jwkset = new JWKSet([
            new JWK(['kty' => 'OKP', 'd' => 'foo']),
            new JWK(['kty' => 'RSA', 'd' => 'foo']),
            new JWK(['kty' => 'EC', 'd' => 'foo']),
        ]);
        $messages = $this->getKeysetAnalyzer()->analyze($jwkset);

        static::assertEmpty($messages);
    }

    /**
     * @test
     */
    public function theKeysetHasOnlyPublicKeys(): void
    {
        $jwkset = new JWKSet([
            new JWK(['kty' => 'OKP']),
            new JWK(['kty' => 'RSA']),
            new JWK(['kty' => 'EC']),
        ]);
        $messages = $this->getKeysetAnalyzer()->analyze($jwkset);

        static::assertEmpty($messages);
    }

    /**
     * @test
     */
    public function theKeysetMixesPublicAndPrivateKeys(): void
    {
        $jwkset = new JWKSet([
            new JWK(['kty' => 'OKP']),
            new JWK(['kty' => 'RSA']),
            new JWK(['kty' => 'EC', 'd' => 'foo']),
        ]);
        $messages = $this->getKeysetAnalyzer()->analyze($jwkset);

        static::assertNotEmpty($messages);
    }

    private function getKeysetAnalyzer(): Analyzer\KeysetAnalyzerManager
    {
        if (null === $this->keysetAnalyzerManager) {
            $this->keysetAnalyzerManager = new Analyzer\KeysetAnalyzerManager();
            $this->keysetAnalyzerManager->add(new Analyzer\MixedPublicAndPrivateKeys());
            $this->keysetAnalyzerManager->add(new Analyzer\MixedKeyTypes());
        }

        return $this->keysetAnalyzerManager;
    }
}
