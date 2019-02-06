<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2019 Spomky-Labs
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
 */
class JWKSetAnalyzerTest extends TestCase
{
    /**
     * @test
     */
    public function theKeysetHasNoKey()
    {
        $jwkset = JWKSet::createFromKeys([]);
        $messages = $this->getKeysetAnalyzer()->analyze($jwkset);

        static::assertEmpty($messages);
    }

    /**
     * @test
     */
    public function theKeysetDoesNotMixesKeys()
    {
        $jwkset = JWKSet::createFromKeys([
            JWK::create(['kty' => 'OKP']),
            JWK::create(['kty' => 'OKP']),
            JWK::create(['kty' => 'EC']),
            JWK::create(['kty' => 'EC']),
        ]);
        $messages = $this->getKeysetAnalyzer()->analyze($jwkset);

        static::assertEmpty($messages);
    }

    /**
     * @test
     */
    public function theKeysetMixesKeys()
    {
        $jwkset = JWKSet::createFromKeys([
            JWK::create(['kty' => 'oct']),
            JWK::create(['kty' => 'OKP']),
            JWK::create(['kty' => 'OKP']),
            JWK::create(['kty' => 'EC']),
            JWK::create(['kty' => 'EC']),
        ]);
        $messages = $this->getKeysetAnalyzer()->analyze($jwkset);

        static::assertNotEmpty($messages);
    }

    /**
     * @test
     */
    public function theKeysetHasOnlyPrivateKeys()
    {
        $jwkset = JWKSet::createFromKeys([
            JWK::create(['kty' => 'OKP', 'd' => 'foo']),
            JWK::create(['kty' => 'RSA', 'd' => 'foo']),
            JWK::create(['kty' => 'EC', 'd' => 'foo']),
        ]);
        $messages = $this->getKeysetAnalyzer()->analyze($jwkset);

        static::assertEmpty($messages);
    }

    /**
     * @test
     */
    public function theKeysetHasOnlyPublicKeys()
    {
        $jwkset = JWKSet::createFromKeys([
            JWK::create(['kty' => 'OKP']),
            JWK::create(['kty' => 'RSA']),
            JWK::create(['kty' => 'EC']),
        ]);
        $messages = $this->getKeysetAnalyzer()->analyze($jwkset);

        static::assertEmpty($messages);
    }

    /**
     * @test
     */
    public function theKeysetMixesPublicAndPrivateKeys()
    {
        $jwkset = JWKSet::createFromKeys([
            JWK::create(['kty' => 'OKP']),
            JWK::create(['kty' => 'RSA']),
            JWK::create(['kty' => 'EC', 'd' => 'foo']),
        ]);
        $messages = $this->getKeysetAnalyzer()->analyze($jwkset);

        static::assertNotEmpty($messages);
    }

    /**
     * @var Analyzer\KeysetAnalyzerManager|null
     */
    private $keysetAnalyzerManager;

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
