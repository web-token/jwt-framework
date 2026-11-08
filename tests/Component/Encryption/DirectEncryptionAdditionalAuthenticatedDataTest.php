<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Encryption;

use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\Encryption\Algorithm\ContentEncryptionAlgorithm;
use Jose\Component\Encryption\Algorithm\KeyEncryption\AESGCMKW;
use Jose\Component\Encryption\JWE;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use function intdiv;
use function restore_error_handler;
use function set_error_handler;
use const E_USER_DEPRECATED;

/**
 * AES-GCM key wrapping encrypts the CEK with AES-GCM and an empty AAD. Without a protected header and without "aad",
 * the content of a "dir" JWE is encrypted the same way: under a key that serves both algorithms, the encrypted key of
 * an A*GCMKW token is a valid "dir" content, and the content of such a "dir" JWE is a valid A*GCMKW encrypted key.
 * Both are still accepted until 5.0.0, with a deprecation.
 *
 * @internal
 */
final class DirectEncryptionAdditionalAuthenticatedDataTest extends EncryptionTestCase
{
    private const PAYLOAD = 'Live long and Prosper.';

    private const KEY = [
        'kty' => 'oct',
        'k' => 'GZy6sIZ6wl9NJOKB-jnmVQ',
    ];

    private const DECRYPTION_DEPRECATION = 'Since web-token/jwt-library 4.3.0: Decrypting a "dir" JWE that has neither a protected header nor additional authenticated data is deprecated and will not be possible in 5.0.0: encrypt it again with "alg" and "enc" in the protected header.';

    private const BUILDING_DEPRECATION = 'Since web-token/jwt-library 4.3.0: Building a "dir" JWE that has neither a protected header nor additional authenticated data is deprecated and will not be possible in 5.0.0: set "alg" and "enc" in the shared protected header.';

    /**
     * The key has no "alg" parameter and the decrypter supports "dir", the key wrapping algorithm and the content
     * encryption algorithm of the same size. The payload of the forged JWE is the CEK of the original token.
     */
    #[DataProvider('keyWrappingAlgorithmsAndSerializations')]
    #[Test]
    public function anAesGcmWrappedKeyPresentedAsDirectContentIsStillDecryptedButDeprecated(
        string $alg,
        string $enc,
        int $keySize,
        string $serializer
    ): void {
        $key = $this->createKey($keySize);
        $token = $this->getJWEBuilderFactory()
            ->create([$alg, $enc])
            ->withPayload(self::PAYLOAD)
            ->withSharedProtectedHeader([
                'alg' => $alg,
                'enc' => $enc,
            ])
            ->addRecipient($key)
            ->build();
        $forged = $this->wrappedKeyAsDirectContent($token, $enc, $serializer);

        $deprecations = $this->collectDeprecations(function () use ($alg, $enc, $forged, $key, $token): void {
            $cek = $this->decrypt(['dir', $alg, $enc], $forged, $key);
            static::assertIsString($cek);
            static::assertSame(self::PAYLOAD, $this->decryptContent($enc, $token, $cek));
        });

        static::assertSame([self::DECRYPTION_DEPRECATION], $deprecations);
    }

    /**
     * The content of the built JWE, with its IV and its tag, is the A*GCMKW encrypted key of its payload.
     */
    #[DataProvider('keyWrappingAlgorithms')]
    #[Test]
    public function aDirectJWEWithoutProtectedHeaderAndWithoutAADIsStillBuiltButDeprecated(
        string $alg,
        string $enc,
        int $keySize
    ): void {
        $key = $this->createKey($keySize);
        $cek = random_bytes(intdiv($keySize, 8));
        $jwe = null;

        $deprecations = $this->collectDeprecations(function () use ($enc, $key, $cek, &$jwe): void {
            $jwe = $this->getJWEBuilderFactory()
                ->create(['dir', $enc])
                ->withPayload($cek)
                ->addRecipient($key, [
                    'alg' => 'dir',
                    'enc' => $enc,
                ])
                ->build();
        });

        static::assertInstanceOf(JWE::class, $jwe);
        $keyWrapping = $this->getAlgorithmManagerFactory()
            ->create([$alg])
            ->get($alg);
        static::assertInstanceOf(AESGCMKW::class, $keyWrapping);
        static::assertSame($cek, $keyWrapping->unwrapKey($key, (string) $jwe->getCiphertext(), [
            'iv' => Base64UrlSafe::encodeUnpadded((string) $jwe->getIV()),
            'tag' => Base64UrlSafe::encodeUnpadded((string) $jwe->getTag()),
        ]));
        static::assertSame([self::BUILDING_DEPRECATION], $deprecations);
    }

    #[DataProvider('contentEncryptionAlgorithms')]
    #[Test]
    public function aDirectJWEWithoutProtectedHeaderAndWithoutAADIsStillDecryptedButDeprecated(
        string $enc,
        int $keySize
    ): void {
        $key = $this->createKey($keySize);

        $deprecations = $this->collectDeprecations(function () use ($enc, $key): void {
            $jwe = $this->getJWEBuilderFactory()
                ->create(['dir', $enc])
                ->withPayload(self::PAYLOAD)
                ->addRecipient($key, [
                    'alg' => 'dir',
                    'enc' => $enc,
                ])
                ->build();
            foreach (['jwe_json_flattened', 'jwe_json_general'] as $serializer) {
                $token = $this->getJWESerializerManager()
                    ->serialize($serializer, $jwe, 0);
                static::assertSame(self::PAYLOAD, $this->decrypt(['dir', $enc], $token, $key));
            }
        });

        static::assertSame(
            [self::BUILDING_DEPRECATION, self::DECRYPTION_DEPRECATION, self::DECRYPTION_DEPRECATION],
            $deprecations
        );
    }

    #[DataProvider('contentEncryptionAlgorithms')]
    #[Test]
    public function aDirectJWEWithAProtectedHeaderOrWithAADIsNotReported(string $enc, int $keySize): void
    {
        $key = $this->createKey($keySize);
        $header = [
            'alg' => 'dir',
            'enc' => $enc,
        ];

        $deprecations = $this->collectDeprecations(function () use ($enc, $key, $header): void {
            $builder = $this->getJWEBuilderFactory()
                ->create(['dir', $enc])
                ->withPayload(self::PAYLOAD);
            $tokens = [
                [$builder->withSharedProtectedHeader($header)->addRecipient($key), 'jwe_compact'],
                [$builder->withSharedProtectedHeader($header)->addRecipient($key), 'jwe_json_general'],
                [
                    $builder->withSharedProtectedHeader([
                        'enc' => $enc,
                    ])->addRecipient($key, [
                        'alg' => 'dir',
                    ]),
                    'jwe_json_flattened',
                ],
                [$builder->withAAD('')->addRecipient($key, $header), 'jwe_json_flattened'],
                [$builder->withAAD(self::PAYLOAD)->addRecipient($key, $header), 'jwe_json_general'],
            ];
            foreach ($tokens as [$tokenBuilder, $serializer]) {
                $token = $this->getJWESerializerManager()
                    ->serialize($serializer, $tokenBuilder->build(), 0);
                static::assertSame(self::PAYLOAD, $this->decrypt(['dir', $enc], $token, $key));
            }
        });

        static::assertSame([], $deprecations);
    }

    /**
     * The AAD of the content is the encoded protected header, followed by a period and the encoded "aad" member when
     * there is one: an empty "protected" member leaves it empty, an empty "aad" member does not. The shared unprotected
     * header is not part of it.
     *
     * @param array<string, mixed> $unprotectedHeader
     * @param list<string> $expectedDeprecations
     */
    #[DataProvider('handMadeTokens')]
    #[Test]
    public function onlyAnEmptyAdditionalAuthenticatedDataIsReported(
        ?string $encodedProtectedHeader,
        ?string $aad,
        array $unprotectedHeader,
        array $expectedDeprecations
    ): void {
        $token = $this->handMadeToken($encodedProtectedHeader, $aad, $unprotectedHeader);

        $deprecations = $this->collectDeprecations(function () use ($token): void {
            static::assertSame(self::PAYLOAD, $this->decrypt(['dir', 'A128GCM'], $token, new JWK(self::KEY)));
        });

        static::assertSame($expectedDeprecations, $deprecations);
    }

    #[Test]
    public function onlyTheKeyThatDecryptsTheTokenIsReported(): void
    {
        $token = $this->handMadeToken(null, null);

        $deprecations = $this->collectDeprecations(function () use ($token): void {
            static::assertNull($this->decrypt(['dir', 'A128GCM'], $token, $this->createKey(128)));
            static::assertSame(
                self::PAYLOAD,
                $this->decrypt(['dir', 'A128GCM'], $token, new JWKSet([$this->createKey(128), new JWK(self::KEY)]))
            );
        });

        static::assertSame([self::DECRYPTION_DEPRECATION], $deprecations);
    }

    /**
     * With two recipients, the "iv" and "tag" of A128GCMKW go to the per-recipient headers and the shared protected
     * header stays empty: the content is encrypted under a random CEK, which is not the key of a recipient.
     */
    #[DataProvider('otherKeyManagementAlgorithms')]
    #[Test]
    public function theOtherKeyManagementModesAreNotReported(string $alg, int $recipients): void
    {
        $keys = [];
        for ($i = 0; $i < $recipients; ++$i) {
            $keys[] = $this->createKey(128);
        }

        $deprecations = $this->collectDeprecations(function () use ($alg, $keys): void {
            $builder = $this->getJWEBuilderFactory()
                ->create([$alg, 'A128GCM'])
                ->withPayload(self::PAYLOAD);
            foreach ($keys as $key) {
                $builder = $builder->addRecipient($key, [
                    'alg' => $alg,
                    'enc' => 'A128GCM',
                ]);
            }
            $token = $this->getJWESerializerManager()
                ->serialize('jwe_json_general', $builder->build());
            foreach ($keys as $index => $key) {
                $result = $this->getJWEDecrypterFactory()
                    ->create(['dir', $alg, 'A128GCM'])
                    ->decrypt($this->getJWESerializerManager()->unserialize($token), $key, $index);
                static::assertSame(self::PAYLOAD, $result->getJwe()->getPayload());
            }
        });

        static::assertSame([], $deprecations);
    }

    /**
     * @return iterable<string, array{string, string, int}>
     */
    public static function keyWrappingAlgorithms(): iterable
    {
        yield 'A128GCMKW and A128GCM' => ['A128GCMKW', 'A128GCM', 128];
        yield 'A192GCMKW and A192GCM' => ['A192GCMKW', 'A192GCM', 192];
        yield 'A256GCMKW and A256GCM' => ['A256GCMKW', 'A256GCM', 256];
    }

    /**
     * @return iterable<string, array{string, string, int, string}>
     */
    public static function keyWrappingAlgorithmsAndSerializations(): iterable
    {
        foreach (self::keyWrappingAlgorithms() as $name => [$alg, $enc, $keySize]) {
            yield $name . ', JSON flattened' => [$alg, $enc, $keySize, 'jwe_json_flattened'];
            yield $name . ', JSON general' => [$alg, $enc, $keySize, 'jwe_json_general'];
        }
    }

    /**
     * @return iterable<string, array{string, int}>
     */
    public static function contentEncryptionAlgorithms(): iterable
    {
        yield 'A128GCM' => ['A128GCM', 128];
        yield 'A192GCM' => ['A192GCM', 192];
        yield 'A256GCM' => ['A256GCM', 256];
        yield 'A128CBC-HS256' => ['A128CBC-HS256', 256];
        yield 'A192CBC-HS384' => ['A192CBC-HS384', 384];
        yield 'A256CBC-HS512' => ['A256CBC-HS512', 512];
    }

    /**
     * @return iterable<string, array{?string, ?string, array<string, mixed>, list<string>}>
     */
    public static function handMadeTokens(): iterable
    {
        yield 'no protected header and no aad' => [null, null, [], [self::DECRYPTION_DEPRECATION]];
        yield 'an empty protected member' => ['', null, [], [self::DECRYPTION_DEPRECATION]];
        yield 'a shared unprotected header only' => [
            null,
            null,
            [
                'kid' => 'key-1',
            ],
            [self::DECRYPTION_DEPRECATION],
        ];
        yield 'a protected header without parameter' => ['e30', null, [], []];
        yield 'a protected header with a parameter' => [
            Base64UrlSafe::encodeUnpadded(JsonConverter::encode([
                'kid' => 'key-1',
            ])),
            null,
            [],
            [],
        ];
        yield 'an empty aad member' => [null, '', [], []];
        yield 'an aad member' => [null, self::PAYLOAD, [], []];
    }

    /**
     * @return iterable<string, array{string, int}>
     */
    public static function otherKeyManagementAlgorithms(): iterable
    {
        yield 'A128KW' => ['A128KW', 1];
        yield 'A128GCMKW, two recipients' => ['A128GCMKW', 2];
    }

    /**
     * @param callable(): void $callback
     *
     * @return list<string>
     */
    private function collectDeprecations(callable $callback): array
    {
        $deprecations = [];
        set_error_handler(static function (int $errno, string $errstr) use (&$deprecations): bool {
            $deprecations[] = $errstr;

            return true;
        }, E_USER_DEPRECATED);

        try {
            $callback();
        } finally {
            restore_error_handler();
        }

        return $deprecations;
    }

    private function createKey(int $keySize): JWK
    {
        return new JWK([
            'kty' => 'oct',
            'k' => Base64UrlSafe::encodeUnpadded(random_bytes(intdiv($keySize, 8))),
        ]);
    }

    private function wrappedKeyAsDirectContent(JWE $token, string $enc, string $serializer): string
    {
        $wrappingHeader = $token->getSharedProtectedHeader();
        $header = [
            'alg' => 'dir',
            'enc' => $enc,
        ];
        $data = [
            'iv' => $wrappingHeader['iv'],
            'ciphertext' => Base64UrlSafe::encodeUnpadded((string) $token->getRecipient(0)->getEncryptedKey()),
            'tag' => $wrappingHeader['tag'],
        ];
        if ($serializer === 'jwe_json_general') {
            $data['recipients'] = [[
                'header' => $header,
            ]];
        } else {
            $data['header'] = $header;
        }

        return JsonConverter::encode($data);
    }

    /**
     * @param array<string, mixed> $unprotectedHeader
     */
    private function handMadeToken(?string $encodedProtectedHeader, ?string $aad, array $unprotectedHeader = []): string
    {
        $iv = random_bytes(12);
        $tag = null;
        $ciphertext = $this->contentEncryptionAlgorithm('A128GCM')
            ->encryptContent(
                self::PAYLOAD,
                Base64UrlSafe::decodeNoPadding(self::KEY['k']),
                $iv,
                $aad,
                $encodedProtectedHeader ?? '',
                $tag
            );
        $data = [
            'header' => [
                'alg' => 'dir',
                'enc' => 'A128GCM',
            ],
            'iv' => Base64UrlSafe::encodeUnpadded($iv),
            'ciphertext' => Base64UrlSafe::encodeUnpadded($ciphertext),
            'tag' => Base64UrlSafe::encodeUnpadded((string) $tag),
        ];
        if ($encodedProtectedHeader !== null) {
            $data['protected'] = $encodedProtectedHeader;
        }
        if ($aad !== null) {
            $data['aad'] = Base64UrlSafe::encodeUnpadded($aad);
        }
        if ($unprotectedHeader !== []) {
            $data['unprotected'] = $unprotectedHeader;
        }

        return JsonConverter::encode($data);
    }

    private function decryptContent(string $enc, JWE $jwe, string $cek): string
    {
        return $this->contentEncryptionAlgorithm($enc)
            ->decryptContent(
                (string) $jwe->getCiphertext(),
                $cek,
                (string) $jwe->getIV(),
                $jwe->getAAD(),
                $jwe->getEncodedSharedProtectedHeader(),
                (string) $jwe->getTag()
            );
    }

    private function contentEncryptionAlgorithm(string $enc): ContentEncryptionAlgorithm
    {
        $algorithm = $this->getAlgorithmManagerFactory()
            ->create([$enc])
            ->get($enc);
        static::assertInstanceOf(ContentEncryptionAlgorithm::class, $algorithm);

        return $algorithm;
    }

    /**
     * @param list<string> $algorithms
     */
    private function decrypt(array $algorithms, string $token, JWK|JWKSet $keys): ?string
    {
        $result = $this->getJWEDecrypterFactory()
            ->create($algorithms)
            ->decrypt($this->getJWESerializerManager()->unserialize($token), $keys, 0);

        return $result->isDecrypted() ? $result->getJwe()
            ->getPayload() : null;
    }
}
