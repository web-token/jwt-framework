<?php

declare(strict_types=1);

namespace Jose\Tests\Component\KeyManagement;

use Brick\Math\BigInteger;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Core\Util\Ecc\NistCurve;
use Jose\Component\KeyManagement\Analyzer\AlgorithmAnalyzer;
use Jose\Component\KeyManagement\Analyzer\ES256KeyAnalyzer;
use Jose\Component\KeyManagement\Analyzer\ES384KeyAnalyzer;
use Jose\Component\KeyManagement\Analyzer\ES512KeyAnalyzer;
use Jose\Component\KeyManagement\Analyzer\HS256KeyAnalyzer;
use Jose\Component\KeyManagement\Analyzer\HS384KeyAnalyzer;
use Jose\Component\KeyManagement\Analyzer\HS512KeyAnalyzer;
use Jose\Component\KeyManagement\Analyzer\KeyAnalyzerManager;
use Jose\Component\KeyManagement\Analyzer\KeyIdentifierAnalyzer;
use Jose\Component\KeyManagement\Analyzer\Message;
use Jose\Component\KeyManagement\Analyzer\NoneAnalyzer;
use Jose\Component\KeyManagement\Analyzer\OctAnalyzer;
use Jose\Component\KeyManagement\Analyzer\RsaAnalyzer;
use Jose\Component\KeyManagement\Analyzer\UsageAnalyzer;
use Jose\Component\KeyManagement\Analyzer\ZxcvbnKeyAnalyzer;
use Jose\Component\KeyManagement\JWKFactory;
use PHPUnit\Framework\Attributes\DoesNotPerformAssertions;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use const STR_PAD_LEFT;

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
    public function theRsaKeyWithLeadingZeroOctetsIsAnalyzedByItsValue(): void
    {
        $key = new JWK([
            'kty' => 'RSA',
            'n' => Base64UrlSafe::encodeUnpadded(str_repeat("\0", 255) . "\x0f"),
            'e' => Base64UrlSafe::encodeUnpadded("\0\0\0\1"),
        ]);
        $messages = $this->getKeyAnalyzer()
            ->analyze($key);

        $texts = array_map(static fn (Message $message): string => $message->getMessage(), $messages->all());
        static::assertContains('The key length is less than 2048 bits.', $texts);
        static::assertContains('The exponent is too low. It should be at least 65537.', $texts);
    }

    #[Test]
    public function theEcKeyWithACoordinateAboveTheFieldPrimeIsRejected(): void
    {
        $key = JWKFactory::createECKey('P-521');
        $prime = NistCurve::curve521()->getPrime();
        $y = BigInteger::fromBase(bin2hex(Base64UrlSafe::decodeNoPadding($key->get('y'))), 16)->plus($prime);
        $y = str_pad(hex2bin(str_pad($y->toBase(16), 132, '0', STR_PAD_LEFT)), 66, "\0", STR_PAD_LEFT);
        $key = new JWK([
            'kty' => 'EC',
            'crv' => 'P-521',
            'x' => $key->get('x'),
            'y' => Base64UrlSafe::encodeUnpadded($y),
        ]);
        $messages = $this->getKeyAnalyzer()
            ->analyze($key);

        $texts = array_map(static fn (Message $message): string => $message->getMessage(), $messages->all());
        static::assertContains(
            'Invalid key. The components "x" and "y" shall be lower than the field prime.',
            $texts
        );
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
