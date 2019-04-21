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
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\KeyManagement\KeyAnalyzer;
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
    public function iCanAnalyzeAnOctKeyAndGetMessages()
    {
        $key = JWKFactory::createOctKey(16, ['use' => 'foo', 'key_ops' => 'foo']);
        $messages = $this->getKeyAnalyzer()->analyze($key);

        static::assertNotEmpty($messages);
    }

    /**
     * @var KeyAnalyzer\KeyAnalyzerManager|null
     */
    private $keyAnalyzerManager;

    private function getKeyAnalyzer(): KeyAnalyzer\KeyAnalyzerManager
    {
        if (null === $this->keyAnalyzerManager) {
            $this->keyAnalyzerManager = new KeyAnalyzer\KeyAnalyzerManager();
            $this->keyAnalyzerManager
                ->add(new KeyAnalyzer\AlgorithmAnalyzer())
                ->add(new KeyAnalyzer\KeyIdentifierAnalyzer())
                ->add(new KeyAnalyzer\NoneAnalyzer())
                ->add(new KeyAnalyzer\OctAnalyzer())
                ->add(new KeyAnalyzer\RsaAnalyzer())
                ->add(new KeyAnalyzer\UsageAnalyzer());
        }

        return $this->keyAnalyzerManager;
    }
}
