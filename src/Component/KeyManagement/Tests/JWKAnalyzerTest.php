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

namespace Jose\Component\KeyManagement\Tests;

use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\Analyzer;
use Jose\Component\KeyManagement\JWKFactory;
use PHPUnit\Framework\TestCase;

/**
 * @group Unit
 * @group JWKAnalyzer
 */
class JWKAnalyzerTest extends TestCase
{
    /**
     * @test
     */
    public function iCanAnalyzeANoneKeyAndGetMessages()
    {
        $key = JWKFactory::createNoneKey();
        $messages = $this->getKeyAnalyzer()->analyze($key);

        static::assertNotEmpty($messages);
    }

    /**
     * @test
     */
    public function iCanAnalyzeAnRsaKeyAndGetMessages()
    {
        $key = JWK::create([
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
    public function iCanAnalyzeAnOctKeyAndGetMessages()
    {
        $key = JWKFactory::createOctKey(16, ['use' => 'foo', 'key_ops' => 'foo']);
        $messages = $this->getKeyAnalyzer()->analyze($key);

        static::assertNotEmpty($messages);
    }

    /**
     * @var Analyzer\KeyAnalyzerManager|null
     */
    private $keyAnalyzerManager;

    private function getKeyAnalyzer(): Analyzer\KeyAnalyzerManager
    {
        if (null === $this->keyAnalyzerManager) {
            $this->keyAnalyzerManager = new Analyzer\KeyAnalyzerManager();
            $this->keyAnalyzerManager
                ->add(new Analyzer\AlgorithmAnalyzer())
                ->add(new Analyzer\KeyIdentifierAnalyzer())
                ->add(new Analyzer\NoneAnalyzer())
                ->add(new Analyzer\OctAnalyzer())
                ->add(new Analyzer\RsaAnalyzer())
                ->add(new Analyzer\UsageAnalyzer());
        }

        return $this->keyAnalyzerManager;
    }
}
