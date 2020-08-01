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
use Jose\Component\KeyManagement\Analyzer;
use Jose\Component\KeyManagement\JWKFactory;
use PHPUnit\Framework\TestCase;

/**
 * @group unit
 * @group JWKAnalyzer
 *
 * @internal
 */
class JWKAnalyzerTest extends TestCase
{
    /**
     * @var null|Analyzer\KeyAnalyzerManager
     */
    private $keyAnalyzerManager;

    /**
     * @test
     */
    public function iCanAnalyzeANoneKeyAndGetMessages(): void
    {
        $key = JWKFactory::createNoneKey();
        $messages = $this->getKeyAnalyzer()->analyze($key);

        static::assertNotEmpty($messages);
    }

    /**
     * @test
     */
    public function iCanAnalyzeAnRsaKeyAndGetMessages(): void
    {
        $key = new JWK([
            'kty' => 'RSA',
            'n' => 'oaAQyGUwgwCfZQym0QQCeCJu6GfApv6nQBKJ3MgzT85kCUO3xDiudiDbJqgqn2ol',
            'e' => 'AQAB',
            'd' => 'asuBS2jRbT50FCkP8PxdRVQ7RIWJ3s5UWAi-c233cQam1kRjGN2QzAv79hrpjLQB',
        ]);
        $messages = $this->getKeyAnalyzer()->analyze($key);

        static::assertNotEmpty($messages);
    }

    /**
     * @test
     */
    public function theRsaKeyHasALowExponent(): void
    {
        $key = JWK::createFromJson('{"kty":"RSA","n":"sv2gihrIZaT4tkxb0B70Aw","e":"Aw","d":"d1PAXBHa7mzdZNOkuSwnSw","p":"4Kz0hhYYddk","q":"y_IaXqREQzs","dp":"lcijBA66-Ts","dq":"h_a8Pxgtgic","qi":"YehXzJzN5bw"}');
        $messages = $this->getKeyAnalyzer()->analyze($key);

        foreach ($messages->all() as $message) {
            if ('The exponent is too low. It should be at least 65537.' === $message->getMessage()) {
                return; // Message found. OK
            }
        }
        static::fail('The low exponent should be catched');
    }

    /**
     * @test
     */
    public function iCanAnalyzeAnOctKeyAndGetMessages(): void
    {
        $key = JWKFactory::createOctKey(16, ['use' => 'foo', 'key_ops' => 'foo']);
        $messages = $this->getKeyAnalyzer()->analyze($key);

        static::assertNotEmpty($messages);
    }

    private function getKeyAnalyzer(): Analyzer\KeyAnalyzerManager
    {
        if (null === $this->keyAnalyzerManager) {
            $this->keyAnalyzerManager = new Analyzer\KeyAnalyzerManager();
            $this->keyAnalyzerManager->add(new Analyzer\AlgorithmAnalyzer());
            $this->keyAnalyzerManager->add(new Analyzer\KeyIdentifierAnalyzer());
            $this->keyAnalyzerManager->add(new Analyzer\NoneAnalyzer());
            $this->keyAnalyzerManager->add(new Analyzer\OctAnalyzer());
            $this->keyAnalyzerManager->add(new Analyzer\RsaAnalyzer());
            $this->keyAnalyzerManager->add(new Analyzer\UsageAnalyzer());
        }

        return $this->keyAnalyzerManager;
    }
}
