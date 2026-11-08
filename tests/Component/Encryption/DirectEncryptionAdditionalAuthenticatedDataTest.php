<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Encryption;

use Jose\Component\Core\Exception\InvalidArgumentException;
use Jose\Component\Core\Exception\InvalidTokenException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\Encryption\Algorithm\ContentEncryptionAlgorithm;
use Jose\Component\Encryption\JWE;
use Jose\Component\Encryption\JWEBuilder;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Throwable;
use function intdiv;

/**
 * AES-GCM key wrapping encrypts the CEK with AES-GCM and an empty AAD. Without a protected header and without "aad",
 * the content of a "dir" JWE would be encrypted the same way: under a key that serves both algorithms, the encrypted key
 * of an A*GCMKW token would be a valid "dir" content, and the content of such a "dir" JWE a valid A*GCMKW encrypted key.
 * Such a JWE is neither built nor decrypted.
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

    private const DECRYPTION_ERROR = 'A "dir" JWE must have a protected header or additional authenticated data.';

    private const BUILDING_ERROR = 'A "dir" JWE must have a protected header or additional authenticated data: set "alg" and "enc" in the shared protected header.';

    /**
     * The key has no "alg" parameter and the decrypter supports "dir", the key wrapping algorithm and the content
     * encryption algorithm of the same size: the CEK of the original token is not returned.
     */
    #[DataProvider('keyWrappingAlgorithmsAndSerializations')]
    #[Test]
    public function anAesGcmWrappedKeyPresentedAsDirectContentIsRefused(
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

        static::assertSame(
            [null, [[InvalidArgumentException::class, self::DECRYPTION_ERROR]]],
            $this->decrypt(['dir', $alg, $enc], $forged, $key)
        );
    }

    #[DataProvider('contentEncryptionAlgorithms')]
    #[Test]
    public function aDirectJWEWithoutProtectedHeaderAndWithoutAADIsNotBuilt(string $enc, int $keySize): void
    {
        $builder = $this->getJWEBuilderFactory()
            ->create(['dir', $enc])
            ->withPayload(self::PAYLOAD)
            ->addRecipient($this->createKey($keySize), [
                'alg' => 'dir',
                'enc' => $enc,
            ]);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(self::BUILDING_ERROR);

        $builder->build();
    }

    /**
     * @param callable(JWEBuilder, JWK): JWEBuilder $configure
     */
    #[DataProvider('otherLayoutsWithoutAAD')]
    #[Test]
    public function theOtherLayoutsWithoutProtectedHeaderAndWithoutAADAreNotBuilt(callable $configure): void
    {
        $builder = $configure(
            $this->getJWEBuilderFactory()
                ->create(['dir', 'A128GCM'])
                ->withPayload(self::PAYLOAD),
            new JWK(self::KEY)
        );

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(self::BUILDING_ERROR);

        $builder->build();
    }

    #[DataProvider('contentEncryptionAlgorithms')]
    #[Test]
    public function aDirectJWEWithoutProtectedHeaderAndWithoutAADIsNotDecrypted(string $enc, int $keySize): void
    {
        $key = $this->createKey($keySize);

        foreach (['jwe_json_flattened', 'jwe_json_general'] as $serializer) {
            static::assertSame(
                [null, [[InvalidArgumentException::class, self::DECRYPTION_ERROR]]],
                $this->decrypt(['dir', $enc], $this->handMadeToken($enc, $key, $serializer, null, null), $key)
            );
        }
    }

    #[DataProvider('contentEncryptionAlgorithms')]
    #[Test]
    public function aDirectJWEWithAProtectedHeaderOrWithAADIsStillBuiltAndDecrypted(string $enc, int $keySize): void
    {
        $key = $this->createKey($keySize);
        $header = [
            'alg' => 'dir',
            'enc' => $enc,
        ];
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
            static::assertSame([self::PAYLOAD, []], $this->decrypt(['dir', $enc], $token, $key));
        }
    }

    /**
     * The AAD of the content is the encoded protected header, followed by a period and the encoded "aad" member when
     * there is one: an empty "protected" member leaves it empty, an empty "aad" member does not. The shared unprotected
     * header is not part of it.
     *
     * @param array<string, mixed> $unprotectedHeader
     */
    #[DataProvider('handMadeTokens')]
    #[Test]
    public function onlyAnEmptyAdditionalAuthenticatedDataIsRefused(
        ?string $encodedProtectedHeader,
        ?string $aad,
        array $unprotectedHeader,
        bool $refused
    ): void {
        $key = new JWK(self::KEY);
        $token = $this->handMadeToken(
            'A128GCM',
            $key,
            'jwe_json_flattened',
            $encodedProtectedHeader,
            $aad,
            $unprotectedHeader
        );

        static::assertSame(
            $refused ? [null, [[InvalidArgumentException::class, self::DECRYPTION_ERROR]]] : [self::PAYLOAD, []],
            $this->decrypt(['dir', 'A128GCM'], $token, $key)
        );
    }

    /**
     * The refusal does not depend on the key: the key that encrypted the token refuses it too, and every key of the key
     * set reports it.
     */
    #[Test]
    public function everyKeyOfTheKeySetRefusesTheToken(): void
    {
        $key = new JWK(self::KEY);
        $token = $this->handMadeToken('A128GCM', $key, 'jwe_json_flattened', null, null);

        static::assertSame(
            [
                null,
                [
                    [InvalidArgumentException::class, self::DECRYPTION_ERROR],
                    [InvalidArgumentException::class, self::DECRYPTION_ERROR],
                ],
            ],
            $this->decrypt(['dir', 'A128GCM'], $token, new JWKSet([$this->createKey(128), $key]))
        );
    }

    #[Test]
    public function theLoaderKeepsTheReasonOfTheRefusal(): void
    {
        $key = new JWK(self::KEY);
        $token = $this->handMadeToken('A128GCM', $key, 'jwe_json_flattened', null, null);
        $loader = $this->getJWELoaderFactory()
            ->create(['jwe_json_flattened'], ['dir', 'A128GCM']);

        try {
            $loader->loadAndDecrypt($token, $key);
            static::fail('The token was decrypted.');
        } catch (InvalidTokenException $exception) {
            $previous = $exception->getPrevious();
            static::assertInstanceOf(InvalidArgumentException::class, $previous);
            static::assertSame(self::DECRYPTION_ERROR, $previous->getMessage());
        }
    }

    /**
     * With two recipients, the "iv" and "tag" of A128GCMKW go to the per-recipient headers and the shared protected
     * header stays empty: the content is encrypted under a random CEK, which is not the key of a recipient.
     */
    #[DataProvider('otherKeyManagementAlgorithms')]
    #[Test]
    public function theOtherKeyManagementModesAreNotRefused(string $alg, int $recipients): void
    {
        $keys = [];
        for ($i = 0; $i < $recipients; ++$i) {
            $keys[] = $this->createKey(128);
        }
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
            static::assertSame(
                [self::PAYLOAD, []],
                $this->decrypt(['dir', $alg, 'A128GCM'], $token, $key, $index)
            );
        }
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
     * @return iterable<string, array{callable(JWEBuilder, JWK): JWEBuilder}>
     */
    public static function otherLayoutsWithoutAAD(): iterable
    {
        yield '"alg" and "enc" in the shared unprotected header' => [
            static fn (JWEBuilder $builder, JWK $key): JWEBuilder => $builder->withSharedHeader([
                'alg' => 'dir',
                'enc' => 'A128GCM',
            ])->addRecipient($key),
        ];
        yield 'an empty shared protected header' => [
            static fn (JWEBuilder $builder, JWK $key): JWEBuilder => $builder->withSharedProtectedHeader([])
                ->addRecipient($key, [
                    'alg' => 'dir',
                    'enc' => 'A128GCM',
                ]),
        ];
        yield 'an "aad" member set back to null' => [
            static fn (JWEBuilder $builder, JWK $key): JWEBuilder => $builder->withAAD(self::PAYLOAD)
                ->withAAD(null)
                ->addRecipient($key, [
                    'alg' => 'dir',
                    'enc' => 'A128GCM',
                ]),
        ];
    }

    /**
     * @return iterable<string, array{?string, ?string, array<string, mixed>, bool}>
     */
    public static function handMadeTokens(): iterable
    {
        yield 'no protected header and no aad' => [null, null, [], true];
        yield 'an empty protected member' => ['', null, [], true];
        yield 'a shared unprotected header only' => [
            null,
            null,
            [
                'kid' => 'key-1',
            ],
            true,
        ];
        yield 'a protected header without parameter' => ['e30', null, [], false];
        yield 'a protected header with a parameter' => [
            Base64UrlSafe::encodeUnpadded(JsonConverter::encode([
                'kid' => 'key-1',
            ])),
            null,
            [],
            false,
        ];
        yield 'an empty aad member' => [null, '', [], false];
        yield 'an aad member' => [null, self::PAYLOAD, [], false];
    }

    /**
     * @return iterable<string, array{string, int}>
     */
    public static function otherKeyManagementAlgorithms(): iterable
    {
        yield 'A128KW' => ['A128KW', 1];
        yield 'A128GCMKW, two recipients' => ['A128GCMKW', 2];
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
     * Encrypts the content as the builder would, so that only the layout of the token decides whether it is refused.
     *
     * @param array<string, mixed> $unprotectedHeader
     */
    private function handMadeToken(
        string $enc,
        JWK $key,
        string $serializer,
        ?string $encodedProtectedHeader,
        ?string $aad,
        array $unprotectedHeader = []
    ): string {
        $algorithm = $this->contentEncryptionAlgorithm($enc);
        $iv = random_bytes(intdiv($algorithm->getIVSize(), 8));
        $tag = null;
        $ciphertext = $algorithm->encryptContent(
            self::PAYLOAD,
            Base64UrlSafe::decodeNoPadding((string) $key->get('k')),
            $iv,
            $aad,
            $encodedProtectedHeader ?? '',
            $tag
        );
        $header = [
            'alg' => 'dir',
            'enc' => $enc,
        ];
        $data = [
            'iv' => Base64UrlSafe::encodeUnpadded($iv),
            'ciphertext' => Base64UrlSafe::encodeUnpadded($ciphertext),
            'tag' => Base64UrlSafe::encodeUnpadded((string) $tag),
        ];
        if ($serializer === 'jwe_json_general') {
            $data['recipients'] = [[
                'header' => $header,
            ]];
        } else {
            $data['header'] = $header;
        }
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
     *
     * @return array{?string, list<array{class-string<Throwable>, string}>}
     */
    private function decrypt(array $algorithms, string $token, JWK|JWKSet $keys, int $recipient = 0): array
    {
        $errors = [];
        $result = $this->getJWEDecrypterFactory()
            ->create($algorithms)
            ->decrypt(
                $this->getJWESerializerManager()
                    ->unserialize($token),
                $keys,
                $recipient,
                null,
                static function (Throwable $throwable) use (&$errors): void {
                    $errors[] = [$throwable::class, $throwable->getMessage()];
                }
            );

        return [$result->isDecrypted() ? $result->getJwe()->getPayload() : null, $errors];
    }
}
