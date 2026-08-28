<?php

declare(strict_types=1);

namespace Jose\Tests\SignatureAlgorithm\HMAC;

use InvalidArgumentException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\Algorithm\HS384;
use Jose\Component\Signature\Algorithm\HS512;
use Jose\Component\Signature\Algorithm\MacAlgorithm;
use Jose\Component\Signature\Algorithm\SignatureAlgorithm;
use Jose\Tests\SignatureAlgorithm\HMAC\Stub\LegacyTruncatedHMAC;
use PHPUnit\Framework\Attributes\IgnoreDeprecations;
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

        $hmac->sign($key, $data);
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

        $signature = $hmac->sign($key, $data);

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

        $signature = $hmac->sign($key, $data);

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

        $signature = $hmac->sign($key, $data);

        static::assertSame(hex2bin(
            'e8b36712b6c6dc422eec77f31ce372ccac769450413238158bd702069630456a148d0c10dd3a661a774217fb90b0d5f94fa6c3c985438bade92ff975b9e4dc04'
        ), $signature);
        static::assertTrue($hmac->verify($key, $data, $signature));
    }

    #[Test]
    public function hmacAlgorithmsAreSignatureAlgorithms(): void
    {
        $hmac = new HS256();

        static::assertInstanceOf(SignatureAlgorithm::class, $hmac);
        static::assertInstanceOf(MacAlgorithm::class, $hmac);
    }

    #[Test]
    #[IgnoreDeprecations]
    public function theDeprecatedHashMethodReturnsTheSignature(): void
    {
        $key = new JWK([
            'kty' => 'oct',
            'k' => Base64UrlSafe::encodeUnpadded(
                'foofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoo'
            ),
        ]);
        $hmac = new HS256();
        $data = 'Live long and Prosper.';

        static::assertSame($hmac->sign($key, $data), $hmac->hash($key, $data));
    }

    #[Test]
    #[IgnoreDeprecations]
    public function anAlgorithmThatOverridesTheDeprecatedHashMethodIsStillHonoured(): void
    {
        $key = new JWK([
            'kty' => 'oct',
            'k' => Base64UrlSafe::encodeUnpadded(
                'foofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoo'
            ),
        ]);
        $hmac = new LegacyTruncatedHMAC();
        $data = 'Live long and Prosper.';

        $signature = $hmac->sign($key, $data);

        static::assertSame($hmac->hash($key, $data), $signature);
        static::assertSame(8, mb_strlen($signature, '8bit'));
        static::assertTrue($hmac->verify($key, $data, $signature));
    }
}
