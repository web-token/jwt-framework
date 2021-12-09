<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Encryption\Algorithm\KeyEncryption;

use InvalidArgumentException;
use Jose\Component\Core\JWK;
use Jose\Component\Encryption\Algorithm\KeyEncryption\Dir;
use ParagonIE\ConstantTime\Base64UrlSafe;
use PHPUnit\Framework\TestCase;

/**
 * Class DirAlgorithmTest.
 *
 * @internal
 */
final class DirAlgorithmTest extends TestCase
{
    /**
     * @test
     */
    public function invalidKey(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Wrong key type.');

        $key = new JWK([
            'kty' => 'EC',
        ]);

        $dir = new Dir();

        $dir->getCEK($key);
    }

    /**
     * @test
     */
    public function validCEK(): void
    {
        $key = new JWK([
            'kty' => 'oct',
            'k' => Base64UrlSafe::encodeUnpadded('ABCD'),
        ]);

        $dir = new Dir();

        static::assertSame('ABCD', $dir->getCEK($key));
    }
}
