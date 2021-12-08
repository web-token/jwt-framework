<?php

declare(strict_types=1);

namespace Jose\Tests\Component\KeyManagement;

use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\Analyzer\AlgorithmAnalyzer;
use Jose\Component\KeyManagement\Analyzer\KeyAnalyzerManager;
use Jose\Component\KeyManagement\Analyzer\KeyIdentifierAnalyzer;
use Jose\Component\KeyManagement\Analyzer\NoneAnalyzer;
use Jose\Component\KeyManagement\Analyzer\OctAnalyzer;
use Jose\Component\KeyManagement\Analyzer\RsaAnalyzer;
use Jose\Component\KeyManagement\Analyzer\UsageAnalyzer;
use Jose\Component\KeyManagement\JWKFactory;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
final class JWKAnalyzerTest extends TestCase
{
    private ?KeyAnalyzerManager $keyAnalyzerManager = null;

    /**
     * @test
     */
    public function iCanAnalyzeANoneKeyAndGetMessages(): void
    {
        $key = JWKFactory::createNoneKey();
        $messages = $this->getKeyAnalyzer()
            ->analyze($key)
        ;

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
        $messages = $this->getKeyAnalyzer()
            ->analyze($key)
        ;

        static::assertNotEmpty($messages);
    }

    /**
     * @test
     */
    public function theRsaKeyHasALowExponent(): void
    {
        $key = JWK::createFromJson(
            '{"kty":"RSA","n":"sv2gihrIZaT4tkxb0B70Aw","e":"Aw","d":"d1PAXBHa7mzdZNOkuSwnSw","p":"4Kz0hhYYddk","q":"y_IaXqREQzs","dp":"lcijBA66-Ts","dq":"h_a8Pxgtgic","qi":"YehXzJzN5bw"}'
        );
        $messages = $this->getKeyAnalyzer()
            ->analyze($key)
        ;

        foreach ($messages->all() as $message) {
            if ($message->getMessage() === 'The exponent is too low. It should be at least 65537.') {
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
        $key = JWKFactory::createOctKey(16, [
            'use' => 'foo',
            'key_ops' => 'foo',
        ]);
        $messages = $this->getKeyAnalyzer()
            ->analyze($key)
        ;

        static::assertNotEmpty($messages);
    }

    private function getKeyAnalyzer(): KeyAnalyzerManager
    {
        if ($this->keyAnalyzerManager === null) {
            $this->keyAnalyzerManager = new KeyAnalyzerManager();
            $this->keyAnalyzerManager->add(new AlgorithmAnalyzer());
            $this->keyAnalyzerManager->add(new KeyIdentifierAnalyzer());
            $this->keyAnalyzerManager->add(new NoneAnalyzer());
            $this->keyAnalyzerManager->add(new OctAnalyzer());
            $this->keyAnalyzerManager->add(new RsaAnalyzer());
            $this->keyAnalyzerManager->add(new UsageAnalyzer());
        }

        return $this->keyAnalyzerManager;
    }
}
