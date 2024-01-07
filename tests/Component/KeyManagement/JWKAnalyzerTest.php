<?php

declare(strict_types=1);

namespace Jose\Tests\Component\KeyManagement;

use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\Analyzer\AlgorithmAnalyzer;
use Jose\Component\KeyManagement\Analyzer\ES256KeyAnalyzer;
use Jose\Component\KeyManagement\Analyzer\ES384KeyAnalyzer;
use Jose\Component\KeyManagement\Analyzer\ES512KeyAnalyzer;
use Jose\Component\KeyManagement\Analyzer\HS256KeyAnalyzer;
use Jose\Component\KeyManagement\Analyzer\HS384KeyAnalyzer;
use Jose\Component\KeyManagement\Analyzer\HS512KeyAnalyzer;
use Jose\Component\KeyManagement\Analyzer\KeyAnalyzerManager;
use Jose\Component\KeyManagement\Analyzer\KeyIdentifierAnalyzer;
use Jose\Component\KeyManagement\Analyzer\NoneAnalyzer;
use Jose\Component\KeyManagement\Analyzer\OctAnalyzer;
use Jose\Component\KeyManagement\Analyzer\RsaAnalyzer;
use Jose\Component\KeyManagement\Analyzer\UsageAnalyzer;
use Jose\Component\KeyManagement\Analyzer\ZxcvbnKeyAnalyzer;
use Jose\Component\KeyManagement\JWKFactory;
use PHPUnit\Framework\Attributes\DoesNotPerformAssertions;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
final class JWKAnalyzerTest extends TestCase
{
    private ?KeyAnalyzerManager $keyAnalyzerManager = null;

    #[Test]
    public function iCanAnalyzeANoneKeyAndGetMessages(): void
    {
        $key = JWKFactory::createNoneKey();
        $messages = $this->getKeyAnalyzer()
            ->analyze($key);

        static::assertNotEmpty($messages);
    }

    #[Test]
    public function iCanAnalyzeAnRsaKeyAndGetMessages(): void
    {
        $key = new JWK([
            'kty' => 'RSA',
            'n' => 'oaAQyGUwgwCfZQym0QQCeCJu6GfApv6nQBKJ3MgzT85kCUO3xDiudiDbJqgqn2ol',
            'e' => 'AQAB',
            'd' => 'asuBS2jRbT50FCkP8PxdRVQ7RIWJ3s5UWAi-c233cQam1kRjGN2QzAv79hrpjLQB',
        ]);
        $messages = $this->getKeyAnalyzer()
            ->analyze($key);

        static::assertNotEmpty($messages);
    }

    #[DoesNotPerformAssertions]
    #[Test]
    public function theRsaKeyHasALowExponent(): void
    {
        $key = JWK::createFromJson(
            '{"kty":"RSA","n":"sv2gihrIZaT4tkxb0B70Aw","e":"Aw","d":"d1PAXBHa7mzdZNOkuSwnSw","p":"4Kz0hhYYddk","q":"y_IaXqREQzs","dp":"lcijBA66-Ts","dq":"h_a8Pxgtgic","qi":"YehXzJzN5bw"}'
        );
        $messages = $this->getKeyAnalyzer()
            ->analyze($key);

        foreach ($messages->all() as $message) {
            if ($message->getMessage() === 'The exponent is too low. It should be at least 65537.') {
                return; // Message found. OK
            }
        }
        static::fail('The low exponent should be catched');
    }

    #[Test]
    public function iCanAnalyzeAnOctKeyAndGetMessages(): void
    {
        $key = JWKFactory::createOctKey(16, [
            'use' => 'foo',
            'key_ops' => 'foo',
        ]);
        $messages = $this->getKeyAnalyzer()
            ->analyze($key);

        static::assertNotEmpty($messages);
    }

    #[Test]
    public function iCanAnalyzeAnES521OctKeyAndGetMessages(): void
    {
        $key = JWKFactory::createECKey('P-521', [
            'kid' => '0123456789',
            'alg' => 'ES521',
            'use' => 'sig',
        ]);
        $messages = $this->getKeyAnalyzer()
            ->analyze($key);
        static::assertEmpty($messages);
    }

    private function getKeyAnalyzer(): KeyAnalyzerManager
    {
        if ($this->keyAnalyzerManager === null) {
            $this->keyAnalyzerManager = new KeyAnalyzerManager();
            $this->keyAnalyzerManager->add(new AlgorithmAnalyzer());
            $this->keyAnalyzerManager->add(new ES256KeyAnalyzer());
            $this->keyAnalyzerManager->add(new ES384KeyAnalyzer());
            $this->keyAnalyzerManager->add(new ES512KeyAnalyzer());
            $this->keyAnalyzerManager->add(new HS256KeyAnalyzer());
            $this->keyAnalyzerManager->add(new HS384KeyAnalyzer());
            $this->keyAnalyzerManager->add(new HS512KeyAnalyzer());
            $this->keyAnalyzerManager->add(new KeyIdentifierAnalyzer());
            $this->keyAnalyzerManager->add(new NoneAnalyzer());
            $this->keyAnalyzerManager->add(new OctAnalyzer());
            $this->keyAnalyzerManager->add(new RsaAnalyzer());
            $this->keyAnalyzerManager->add(new UsageAnalyzer());
            $this->keyAnalyzerManager->add(new ZxcvbnKeyAnalyzer());
        }

        return $this->keyAnalyzerManager;
    }
}
