<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Encryption;

use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Core\Util\ECKey;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHES;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHESA256KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHSS;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use RuntimeException;

/**
 * Without GMP, the PHP implementation of the curves takes seconds for a coordinate of a few hundred bytes. OpenSSL
 * cannot load a private key whose "d" has a leading zero byte: such a key goes through the PHP implementation. The
 * keys come from RFC 7518 appendix C (P-256) and RFC 7520 (P-384 and P-521).
 *
 * @internal
 */
final class ECDHESEphemeralKeyTest extends TestCase
{
    private const CURVES = [
        'P-256' => 32,
        'P-384' => 48,
        'P-521' => 66,
    ];

    private const PRIVATE_KEYS = [
        'P-256' => [
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ',
            'y' => 'e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck',
            'd' => 'VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw',
        ],
        'P-384' => [
            'kty' => 'EC',
            'crv' => 'P-384',
            'x' => 'YU4rRUzdmVqmRtWOs2OpDE_T5fsNIodcG8G5FWPrTPMyxpzsSOGaQLpe2FpxBmu2',
            'y' => 'A8-yxCHxkfBz3hKZfI1jUYMjUhsEveZ9THuwFjH2sCNdtksRJU7D5-SkgaFL1ETP',
            'd' => 'iTx2pk7wW-GqJkHcEkFQb2EFyYcO7RugmaW3mRrQVAOUiPommT0IdnYK2xDlZh-j',
        ],
        'P-521' => [
            'kty' => 'EC',
            'crv' => 'P-521',
            'x' => 'AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt',
            'y' => 'AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1',
            'd' => 'AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zbKipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt',
        ],
    ];

    private const EPHEMERAL_PUBLIC_KEY = [
        'kty' => 'EC',
        'crv' => 'P-256',
        'x' => 'gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0',
        'y' => 'SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps',
    ];

    #[Test]
    #[DataProvider('ephemeralKeysRefusedByOpenSSL')]
    public function anEphemeralKeyRefusedByOpenSSLIsNotCheckedAgainInPhp(string $crv, string $x, string $y): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Unable to derive the key');

        (new ECDHES())->getAgreementKey(128, 'A128GCM', new JWK(self::PRIVATE_KEYS[$crv]), null, self::header(
            $crv,
            $x,
            $y
        ));
    }

    /**
     * @return iterable<string, array{string, string, string}>
     */
    public static function ephemeralKeysRefusedByOpenSSL(): iterable
    {
        foreach (self::CURVES as $crv => $size) {
            yield $crv . ', not on the curve' => [$crv, str_repeat("\x01", $size), str_repeat("\x01", $size)];
            yield $crv . ', x longer than the curve' => [
                $crv,
                str_repeat("\xff", $size + 1),
                str_repeat("\x01", $size),
            ];
            yield $crv . ', y longer than the curve' => [
                $crv,
                str_repeat("\x01", $size),
                str_repeat("\xff", $size + 1),
            ];
        }
    }

    #[Test]
    public function theKeyWrappingVariantsGetTheSameRefusal(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Unable to derive the key');

        (new ECDHESA256KW())->unwrapAgreementKey(
            new JWK(self::PRIVATE_KEYS['P-256']),
            null,
            random_bytes(40),
            256,
            self::header('P-256', str_repeat("\x01", 32), str_repeat("\x01", 32))
        );
    }

    #[Test]
    public function aStaticKeyAgreementBetweenTwoCurvesIsRefused(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Unable to derive the key');

        (new ECDHSS())->getAgreementKey(
            128,
            'A128GCM',
            (new JWK(self::PRIVATE_KEYS['P-256']))->toPublic(),
            new JWK(self::PRIVATE_KEYS['P-384'])
        );
    }

    #[Test]
    #[DataProvider('coordinatesLongerThanTheCurve')]
    public function thePhpImplementationRefusesACoordinateLongerThanTheCurve(string $crv, string $x, string $y): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Unable to derive the key');

        (new ECDHES())->getAgreementKey(
            128,
            'A128GCM',
            new JWK(self::withLeadingZeroInD(self::PRIVATE_KEYS[$crv])),
            null,
            self::header($crv, $x, $y)
        );
    }

    /**
     * @return iterable<string, array{string, string, string}>
     */
    public static function coordinatesLongerThanTheCurve(): iterable
    {
        foreach (self::CURVES as $crv => $size) {
            yield $crv . ', x' => [$crv, "\x01" . str_repeat("\0", $size), str_repeat("\x01", $size)];
            yield $crv . ', y' => [$crv, str_repeat("\x01", $size), "\x01" . str_repeat("\0", $size)];
        }
    }

    #[Test]
    public function aPrivateKeyOpenSSLCannotLoadIsStillUsedByThePhpImplementation(): void
    {
        $recipientKey = self::withLeadingZeroInD(self::PRIVATE_KEYS['P-256']);

        static::assertFalse(openssl_pkey_get_private(ECKey::convertPrivateKeyToPEM(new JWK($recipientKey))));
        static::assertSame('VqqN6vgjbSBcIijNcacQGg', self::derivedKey($recipientKey, self::EPHEMERAL_PUBLIC_KEY));
    }

    /**
     * @param array<string, string> $recipientKey
     */
    #[Test]
    #[DataProvider('recipientKeys')]
    public function aCoordinateWithALeadingZeroByteIsStillAccepted(array $recipientKey): void
    {
        $ephemeralPublicKey = self::EPHEMERAL_PUBLIC_KEY;
        $ephemeralPublicKey['x'] = Base64UrlSafe::encodeUnpadded(
            "\0" . Base64UrlSafe::decodeNoPadding($ephemeralPublicKey['x'])
        );

        static::assertSame('VqqN6vgjbSBcIijNcacQGg', self::derivedKey($recipientKey, $ephemeralPublicKey));
    }

    /**
     * @return iterable<string, array{array<string, string>}>
     */
    public static function recipientKeys(): iterable
    {
        yield 'OpenSSL' => [self::PRIVATE_KEYS['P-256']];
        yield 'PHP implementation' => [self::withLeadingZeroInD(self::PRIVATE_KEYS['P-256'])];
    }

    /**
     * @param array<string, string> $key
     * @return array<string, string>
     */
    private static function withLeadingZeroInD(array $key): array
    {
        $key['d'] = Base64UrlSafe::encodeUnpadded("\0" . Base64UrlSafe::decodeNoPadding($key['d']));

        return $key;
    }

    /**
     * @param array<string, string> $recipientKey
     * @param array<string, string> $ephemeralPublicKey
     */
    private static function derivedKey(array $recipientKey, array $ephemeralPublicKey): string
    {
        return Base64UrlSafe::encodeUnpadded((new ECDHES())->getAgreementKey(128, 'A128GCM', new JWK(
            $recipientKey
        ), null, [
            'alg' => 'ECDH-ES',
            'enc' => 'A128GCM',
            'apu' => 'QWxpY2U',
            'apv' => 'Qm9i',
            'epk' => $ephemeralPublicKey,
        ]));
    }

    /**
     * @return array<string, mixed>
     */
    private static function header(string $crv, string $x, string $y): array
    {
        return [
            'alg' => 'ECDH-ES',
            'enc' => 'A128GCM',
            'epk' => [
                'kty' => 'EC',
                'crv' => $crv,
                'x' => Base64UrlSafe::encodeUnpadded($x),
                'y' => Base64UrlSafe::encodeUnpadded($y),
            ],
        ];
    }
}
