<?php

declare(strict_types=1);

namespace Jose\Tests\Component\KeyManagement\Keys;

use InvalidArgumentException;
use Jose\Component\KeyManagement\JWKFactory;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
final class OKPKeysTest extends TestCase
{
    #[Test]
    public function createOKPKeyWithInvalidKeySize(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Unsupported "Ed455" curve');

        JWKFactory::createOKPKey('Ed455');
    }

    #[Test]
    public function createOKPKeyWithCurveX25519(): void
    {
        $jwk = JWKFactory::createOKPKey('X25519', [
            'kid' => 'KEY',
            'alg' => 'ECDH-ES',
            'use' => 'enc',
        ]);

        static::assertSame('OKP', $jwk->get('kty'));
        static::assertTrue($jwk->has('x'));
        static::assertTrue($jwk->has('d'));
        static::assertSame('KEY', $jwk->get('kid'));
        static::assertSame('ECDH-ES', $jwk->get('alg'));
        static::assertSame('enc', $jwk->get('use'));
    }

    #[Test]
    public function createOKPKeyWithCurveEd25519(): void
    {
        $jwk = JWKFactory::createOKPKey('Ed25519', [
            'kid' => 'KEY',
            'alg' => 'EdDSA',
            'use' => 'sig',
        ]);

        static::assertSame('OKP', $jwk->get('kty'));
        static::assertTrue($jwk->has('x'));
        static::assertTrue($jwk->has('d'));
        static::assertSame('KEY', $jwk->get('kid'));
        static::assertSame('EdDSA', $jwk->get('alg'));
        static::assertSame('sig', $jwk->get('use'));
    }
}
