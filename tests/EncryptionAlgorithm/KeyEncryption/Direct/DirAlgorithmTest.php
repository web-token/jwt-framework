<?php

declare(strict_types=1);

namespace Jose\Tests\EncryptionAlgorithm\KeyEncryption\Direct;

use InvalidArgumentException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Encryption\Algorithm\KeyEncryption\Dir;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Class DirAlgorithmTest.
 *
 * @internal
 */
final class DirAlgorithmTest extends TestCase
{
    #[Test]
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

    #[Test]
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
