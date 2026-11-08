<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Core\Util;

use Jose\Component\Core\Util\Base64UrlSafe;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use RangeException;
use function chr;
use function hex2bin;
use function sprintf;
use function str_contains;

/**
 * @internal
 */
final class Base64UrlSafeTest extends TestCase
{
    private const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

    #[Test]
    #[DataProvider('validEncodings')]
    public function aValidStringIsDecoded(string $unpadded, string $padded, string $binary): void
    {
        static::assertSame($binary, Base64UrlSafe::decodeNoPadding($unpadded));
        static::assertSame($binary, Base64UrlSafe::decode($unpadded, true));
        static::assertSame($binary, Base64UrlSafe::decode($padded, true));
        static::assertSame($binary, Base64UrlSafe::decode($unpadded));
    }

    /**
     * @param callable(string): string $decode
     */
    #[Test]
    #[DataProvider('decoders')]
    public function everyByteOutsideTheAlphabetIsRejected(callable $decode): void
    {
        $accepted = [];
        for ($byte = 0; $byte < 256; ++$byte) {
            $character = chr($byte);
            if ($character === '=' || str_contains(self::ALPHABET, $character)) {
                continue;
            }
            try {
                $decode('QUJ' . $character);
                $accepted[] = sprintf('0x%02X', $byte);
            } catch (RangeException) {
            }
        }

        static::assertSame([], $accepted);
    }

    /**
     * @return iterable<string, array{string, string, string}>
     */
    public static function validEncodings(): iterable
    {
        yield 'one byte' => ['QQ', 'QQ==', 'A'];
        yield 'two bytes' => ['QUI', 'QUI=', 'AB'];
        yield 'three bytes' => ['QUJD', 'QUJD', 'ABC'];
        yield 'the whole alphabet' => [
            self::ALPHABET,
            self::ALPHABET,
            (string) hex2bin(
                '00108310518720928b30d38f41149351559761969b71d79f8218a39259a7a29aabb2dbafc31cb3d35db7e39ebbf3dfbf'
            ),
        ];
    }

    /**
     * @return iterable<string, array{callable(string): string}>
     */
    public static function decoders(): iterable
    {
        yield 'decodeNoPadding' => [Base64UrlSafe::decodeNoPadding(...)];
        yield 'decode with strict padding' => [
            static fn (string $encoded): string => Base64UrlSafe::decode($encoded, true),
        ];
        yield 'decode' => [
            static fn (string $encoded): string => Base64UrlSafe::decode($encoded),
        ];
    }
}
