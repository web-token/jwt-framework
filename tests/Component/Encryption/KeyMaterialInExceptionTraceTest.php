<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Encryption;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A128CBCHS256;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A128GCM;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A256GCM;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A128KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\Dir;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHES;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHESA128KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHSSA128KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\PBES2HS256A128KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\Util\ConcatKDF;
use Jose\Component\Encryption\JWE;
use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\Encryption\JWELoader;
use Jose\Component\Encryption\Serializer\CompactSerializer;
use Jose\Component\Encryption\Serializer\JWESerializerManager;
use Jose\Tests\Component\Core\ExceptionTraceArgumentsTrait;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Throwable;
use function array_map;
use function chr;
use function hash_pbkdf2;
use function implode;
use function ord;
use function str_repeat;

/**
 * A rejected token must not leave a key among the arguments recorded in the traces of the exception chain: neither
 * a key of the application, which a token made of arbitrary bytes reaches, nor the content encryption key of an
 * issued token whose tag or header was altered.
 *
 * The elliptic curve keys and the shared secret are the ones of RFC 7518 appendix C.
 *
 * @internal
 */
final class KeyMaterialInExceptionTraceTest extends TestCase
{
    use ExceptionTraceArgumentsTrait;

    private const DIR_KEY = 'dir-key-01234567';

    private const DIR_KEY_CBC = 'dir-key-for-A128CBC-HS256-012345';

    private const KEK = 'kek-A128KW-01234';

    private const PASSWORD = 'pbes2-password';

    private const SALT = 'salt-chosen-by-the-sender';

    private const CEK = 'cek-of-the-token';

    private const PAYLOAD = 'Live long and prosper.';

    private const RECIPIENT_KEY = [
        'kty' => 'EC',
        'crv' => 'P-256',
        'x' => 'weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ',
        'y' => 'e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck',
        'd' => 'VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw',
    ];

    private const EPHEMERAL_PUBLIC_KEY = [
        'kty' => 'EC',
        'crv' => 'P-256',
        'x' => 'gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0',
        'y' => 'SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps',
    ];

    private const SHARED_SECRET = 'nlbZHYFxNdNyg0KDv4QmnPsxbqPagGpI9tqneYz-kMQ';

    /**
     * @param array<string, string> $secrets
     */
    #[Test]
    #[DataProvider('rejectedTokens')]
    public function noKeyIsAmongTheRecordedArguments(string $token, JWK $key, array $secrets): void
    {
        $exception = self::failureOf(static fn (): JWE => self::loader()->loadAndDecryptWithKey($token, $key, $recipient));

        static::assertNotSame([], self::callsHolding($exception, $token), 'The arguments are not recorded.');
        static::assertSame(
            array_map(static fn (): array => [], $secrets),
            array_map(static fn (string $secret): array => self::callsHolding($exception, $secret), $secrets)
        );
    }

    /**
     * The failures met with each key are handed to the callable given to the decrypter, as with the static key
     * agreement, that the loader does not support.
     */
    #[Test]
    public function noKeyAgreedWithTheSenderIsAmongTheRecordedArguments(): void
    {
        $encryptedKey = str_repeat('k', 24);
        $jwe = (new CompactSerializer())->unserialize(self::token([
            'alg' => 'ECDH-SS+A128KW',
            'enc' => 'A128GCM',
        ], $encryptedKey, str_repeat('i', 12), 'arbitrary', str_repeat('t', 16)));
        $failures = [];

        $decrypted = self::decrypter()->decryptUsingKeySet(
            $jwe,
            new JWKSet([new JWK(self::EPHEMERAL_PUBLIC_KEY)]),
            0,
            $jwk,
            new JWK(self::RECIPIENT_KEY),
            static function (Throwable $failure) use (&$failures): void {
                $failures[] = $failure;
            }
        );

        static::assertFalse($decrypted);
        static::assertCount(1, $failures);
        $sharedSecret = Base64UrlSafe::decodeNoPadding(self::SHARED_SECRET);
        static::assertNotSame([], self::callsHolding($failures[0], $encryptedKey), 'The arguments are not recorded.');
        static::assertSame([
            'shared secret' => [],
            'key encryption key' => [],
        ], [
            'shared secret' => self::callsHolding($failures[0], $sharedSecret),
            'key encryption key' => self::callsHolding(
                $failures[0],
                ConcatKDF::generate($sharedSecret, 'ECDH-SS+A128KW', 128)
            ),
        ]);
    }

    #[Test]
    public function theIssuedTokenIsAccepted(): void
    {
        [$header, $encryptedKey, $iv, $ciphertext, $tag] = self::issuedToken();

        $jwe = self::loader()->loadAndDecryptWithKey(
            self::compact($header, $encryptedKey, $iv, $ciphertext, $tag),
            self::octKey(self::KEK),
            $recipient
        );

        static::assertSame(self::PAYLOAD, $jwe->getPayload());
    }

    /**
     * @return iterable<string, array{string, JWK, array<string, string>}>
     */
    public static function rejectedTokens(): iterable
    {
        $arbitraryIv = str_repeat('i', 12);
        $arbitraryTag = str_repeat('t', 16);

        yield 'dir with A128GCM' => [
            self::token([
                'alg' => 'dir',
                'enc' => 'A128GCM',
            ], '', $arbitraryIv, 'arbitrary', $arbitraryTag),
            self::octKey(self::DIR_KEY),
            [
                'dir key' => self::DIR_KEY,
            ],
        ];
        yield 'dir with A128CBC-HS256' => [
            self::token(
                [
                    'alg' => 'dir',
                    'enc' => 'A128CBC-HS256',
                ],
                '',
                str_repeat('i', 16),
                str_repeat('c', 16),
                $arbitraryTag
            ),
            self::octKey(self::DIR_KEY_CBC),
            [
                'dir key' => self::DIR_KEY_CBC,
            ],
        ];
        foreach ([
            24 => 'that fails the integrity check',
            8 => 'of one block',
            20 => 'of 20 bytes',
        ] as $size => $label) {
            yield 'A128KW with an encrypted key ' . $label => [
                self::token(
                    [
                        'alg' => 'A128KW',
                        'enc' => 'A128GCM',
                    ],
                    str_repeat('k', $size),
                    $arbitraryIv,
                    'arbitrary',
                    $arbitraryTag
                ),
                self::octKey(self::KEK),
                [
                    'key encryption key' => self::KEK,
                ],
            ];
        }
        yield 'PBES2-HS256+A128KW with the salt and count of the sender' => [
            self::token(
                [
                    'alg' => 'PBES2-HS256+A128KW',
                    'enc' => 'A128GCM',
                    'p2s' => Base64UrlSafe::encodeUnpadded(self::SALT),
                    'p2c' => 1,
                ],
                str_repeat('k', 24),
                $arbitraryIv,
                'arbitrary',
                $arbitraryTag
            ),
            self::octKey(self::PASSWORD),
            [
                'derived key' => hash_pbkdf2(
                    'sha256',
                    self::PASSWORD,
                    'PBES2-HS256+A128KW' . "\x00" . self::SALT,
                    1,
                    16,
                    true
                ),
            ],
        ];

        $sharedSecret = Base64UrlSafe::decodeNoPadding(self::SHARED_SECRET);
        yield 'ECDH-ES+A128KW with an encrypted key that does not unwrap' => [
            self::token(
                [
                    'alg' => 'ECDH-ES+A128KW',
                    'enc' => 'A128GCM',
                    'epk' => self::EPHEMERAL_PUBLIC_KEY,
                    'apu' => 'QWxpY2U',
                    'apv' => 'Qm9i',
                ],
                str_repeat('k', 24),
                $arbitraryIv,
                'arbitrary',
                $arbitraryTag
            ),
            new JWK(self::RECIPIENT_KEY),
            [
                'shared secret' => $sharedSecret,
                'key encryption key' => ConcatKDF::generate($sharedSecret, 'ECDH-ES+A128KW', 128, 'QWxpY2U', 'Qm9i'),
            ],
        ];
        yield 'ECDH-ES with an "apu" that is not base64url' => [
            self::token(
                [
                    'alg' => 'ECDH-ES',
                    'enc' => 'A128GCM',
                    'epk' => self::EPHEMERAL_PUBLIC_KEY,
                    'apu' => '*',
                ],
                '',
                $arbitraryIv,
                'arbitrary',
                $arbitraryTag
            ),
            new JWK(self::RECIPIENT_KEY),
            [
                'shared secret' => $sharedSecret,
            ],
        ];

        [$header, $encryptedKey, $iv, $ciphertext, $tag] = self::issuedToken();
        $alteredTag = $tag;
        $alteredTag[0] = chr(ord($tag[0]) ^ 1);
        yield 'issued token with an altered tag' => [
            self::compact($header, $encryptedKey, $iv, $ciphertext, $alteredTag),
            self::octKey(self::KEK),
            [
                'content encryption key' => self::CEK,
                'key encryption key' => self::KEK,
            ],
        ];
        yield 'issued token with another "enc"' => [
            self::compact(
                Base64UrlSafe::encodeUnpadded(JsonConverter::encode([
                    'alg' => 'A128KW',
                    'enc' => 'A256GCM',
                ])),
                $encryptedKey,
                $iv,
                $ciphertext,
                $tag
            ),
            self::octKey(self::KEK),
            [
                'content encryption key' => self::CEK,
                'key encryption key' => self::KEK,
            ],
        ];
    }

    private static function loader(): JWELoader
    {
        return new JWELoader(new JWESerializerManager([new CompactSerializer()]), self::decrypter(), null);
    }

    private static function decrypter(): JWEDecrypter
    {
        return new JWEDecrypter(new AlgorithmManager([
            new Dir(),
            new A128KW(),
            new PBES2HS256A128KW(),
            new ECDHES(),
            new ECDHESA128KW(),
            new ECDHSSA128KW(),
            new A128GCM(),
            new A256GCM(),
            new A128CBCHS256(),
        ]));
    }

    /**
     * A token issued to the application under the key encryption key, with a known content encryption key.
     *
     * @return array{string, string, string, string, string}
     */
    private static function issuedToken(): array
    {
        $header = [
            'alg' => 'A128KW',
            'enc' => 'A128GCM',
        ];
        $encodedHeader = Base64UrlSafe::encodeUnpadded(JsonConverter::encode($header));
        $additionalHeader = [];
        $encryptedKey = (new A128KW())->wrapKey(self::octKey(self::KEK), self::CEK, $header, $additionalHeader);
        $iv = str_repeat('i', 12);
        $tag = null;
        $ciphertext = (new A128GCM())->encryptContent(self::PAYLOAD, self::CEK, $iv, null, $encodedHeader, $tag);

        return [$encodedHeader, $encryptedKey, $iv, $ciphertext, (string) $tag];
    }

    /**
     * @param array<string, mixed> $header
     */
    private static function token(
        array $header,
        string $encryptedKey,
        string $iv,
        string $ciphertext,
        string $tag
    ): string {
        return self::compact(
            Base64UrlSafe::encodeUnpadded(JsonConverter::encode($header)),
            $encryptedKey,
            $iv,
            $ciphertext,
            $tag
        );
    }

    private static function compact(
        string $encodedHeader,
        string $encryptedKey,
        string $iv,
        string $ciphertext,
        string $tag
    ): string {
        return implode('.', [
            $encodedHeader,
            Base64UrlSafe::encodeUnpadded($encryptedKey),
            Base64UrlSafe::encodeUnpadded($iv),
            Base64UrlSafe::encodeUnpadded($ciphertext),
            Base64UrlSafe::encodeUnpadded($tag),
        ]);
    }

    private static function octKey(string $key): JWK
    {
        return new JWK([
            'kty' => 'oct',
            'k' => Base64UrlSafe::encodeUnpadded($key),
        ]);
    }
}
