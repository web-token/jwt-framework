<?php

declare(strict_types=1);

namespace Jose\Tests\SignatureAlgorithm\HMAC;

use InvalidArgumentException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\Algorithm\HS384;
use Jose\Component\Signature\Algorithm\HS512;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
final class HMACSignatureTest extends TestCase
{
    #[Test]
    public function invalidKey(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Wrong key type.');
        $key = new JWK([
            'kty' => 'EC',
        ]);

        $hmac = new HS256();
        $data = 'Live long and Prosper.';

        $hmac->hash($key, $data);
    }

    #[Test]
    public function signatureHasBadBadLength(): void
    {
        $key = new JWK([
            'kty' => 'oct',
            'k' => Base64UrlSafe::encodeUnpadded(
                'foofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoo'
            ),
        ]);
        $hmac = new HS256();
        $data = 'Live long and Prosper.';

        static::assertFalse($hmac->verify($key, $data, hex2bin('326eb338c465d3587f3349df0b96ba81')));
    }

    #[Test]
    public function hS256SignAndVerify(): void
    {
        $key = new JWK([
            'kty' => 'oct',
            'k' => Base64UrlSafe::encodeUnpadded(
                'foofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoo'
            ),
        ]);
        $hmac = new HS256();
        $data = 'Live long and Prosper.';

        $signature = $hmac->hash($key, $data);

        static::assertTrue($hmac->verify($key, $data, $signature));
    }

    #[Test]
    public function hS384SignAndVerify(): void
    {
        $key = new JWK([
            'kty' => 'oct',
            'k' => Base64UrlSafe::encodeUnpadded(
                'foofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoo'
            ),
        ]);
        $hmac = new HS384();
        $data = 'Live long and Prosper.';

        $signature = $hmac->hash($key, $data);

        static::assertTrue($hmac->verify($key, $data, $signature));
    }

    #[Test]
    public function hS512SignAndVerify(): void
    {
        $key = new JWK([
            'kty' => 'oct',
            'k' => 'foofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoo',
        ]);
        $hmac = new HS512();
        $data = 'Live long and Prosper.';

        $signature = $hmac->hash($key, $data);

        static::assertSame(hex2bin(
            'e8b36712b6c6dc422eec77f31ce372ccac769450413238158bd702069630456a148d0c10dd3a661a774217fb90b0d5f94fa6c3c985438bade92ff975b9e4dc04'
        ), $signature);
        static::assertTrue($hmac->verify($key, $data, $signature));
    }
}
