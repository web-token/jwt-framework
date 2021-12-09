<?php

declare(strict_types=1);

namespace Jose\Tests\Component\KeyManagement\Keys;

use InvalidArgumentException;
use Jose\Component\KeyManagement\JWKFactory;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
final class OctKeysTest extends TestCase
{
    /**
     * @test
     */
    public function createOctKeyWithInvalidKeySize(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid key size.');

        JWKFactory::createOctKey(12);
    }

    /**
     * @test
     */
    public function createOctKey(): void
    {
        $jwk = JWKFactory::createOctKey(64);

        static::assertSame('oct', $jwk->get('kty'));
        static::assertTrue($jwk->has('k'));
    }
}
