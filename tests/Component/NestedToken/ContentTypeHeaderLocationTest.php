<?php

declare(strict_types=1);

namespace Jose\Tests\Component\NestedToken;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\Exception\InvalidArgumentException;
use Jose\Component\Core\Exception\InvalidHeaderParameterException;
use Jose\Component\Core\Exception\InvalidTokenException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A128GCM;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A128KW;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\Encryption\JWELoader;
use Jose\Component\Encryption\Serializer\CompactSerializer as JWECompactSerializer;
use Jose\Component\Encryption\Serializer\JSONFlattenedSerializer;
use Jose\Component\Encryption\Serializer\JSONGeneralSerializer;
use Jose\Component\Encryption\Serializer\JWESerializer;
use Jose\Component\Encryption\Serializer\JWESerializerManager;
use Jose\Component\NestedToken\NestedTokenLoader;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWSLoader;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Throwable;
use const E_USER_DEPRECATED;

/**
 * A JWE carries a nested token when its "cty" header parameter is "JWT". The authentication tag covers the protected
 * header only: a "cty" in the shared unprotected header or in a recipient header of a JSON serialization can be added
 * to a token without any key. Such a token is still loaded until 5.0.0, with a deprecation.
 *
 * @internal
 */
final class ContentTypeHeaderLocationTest extends TestCase
{
    private const CLAIMS = '{"iss":"issuer.example","sub":"alice"}';

    private const ENCRYPTION_KEY = 'kek-A128KW-01234';

    private const OTHER_ENCRYPTION_KEY = 'kek-A128KW-56789';

    private const SIGNATURE_KEY = 'the HS256 key of the issuer of the token';

    private const OTHER_SIGNATURE_KEY = 'the HS256 key of someone else entirely';

    #[Test]
    #[DataProvider('protectedContentTypes')]
    public function aTokenMarkedInTheProtectedHeaderLoadsWithoutDeprecation(string $token): void
    {
        $deprecations = $this->collectDeprecations(static function () use ($token): void {
            static::assertSame(self::CLAIMS, self::load($token)->getPayload());
        });

        static::assertSame([], $deprecations);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function protectedContentTypes(): iterable
    {
        yield 'compact' => [self::encrypt(new JWECompactSerializer(), [
            'cty' => 'JWT',
        ])];
        yield 'JSON flattened' => [self::encrypt(new JSONFlattenedSerializer(), [
            'cty' => 'JWT',
        ])];
        yield 'JSON general' => [self::encrypt(new JSONGeneralSerializer(), [
            'cty' => 'JWT',
        ])];
        yield 'lower case' => [self::encrypt(new JWECompactSerializer(), [
            'cty' => 'jwt',
        ])];
        yield 'next to unprotected header parameters' => [self::encrypt(new JSONGeneralSerializer(), [
            'cty' => 'JWT',
        ], [
            'x-shared' => 'shared',
        ], [
            'x-recipient' => 'recipient',
        ])];
    }

    /**
     * Until 5.0.0, a "cty" outside the protected header still marks a nested token: the token loads as before.
     */
    #[Test]
    #[DataProvider('unprotectedContentTypes')]
    public function aTokenMarkedOutsideTheProtectedHeaderIsDeprecated(string $token): void
    {
        $deprecations = $this->collectDeprecations(static function () use ($token): void {
            static::assertSame(self::CLAIMS, self::load($token)->getPayload());
        });

        static::assertCount(1, $deprecations);
        static::assertStringContainsString(
            'nested token whose "cty" header parameter is not in the protected header',
            $deprecations[0]
        );
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function unprotectedContentTypes(): iterable
    {
        yield 'shared unprotected header, JSON flattened' => [self::encrypt(new JSONFlattenedSerializer(), [], [
            'cty' => 'JWT',
        ])];
        yield 'recipient header, JSON flattened' => [self::encrypt(new JSONFlattenedSerializer(), [], [], [
            'cty' => 'JWT',
        ])];
        yield 'shared unprotected header, JSON general' => [self::encrypt(new JSONGeneralSerializer(), [], [
            'cty' => 'JWT',
        ])];
        yield 'recipient header, JSON general' => [self::encrypt(new JSONGeneralSerializer(), [], [], [
            'cty' => 'JWT',
        ])];
        yield 'lower case' => [self::encrypt(new JSONFlattenedSerializer(), [], [
            'cty' => 'jwt',
        ])];
        yield 'header of the decrypted recipient' => [self::encryptForTwoRecipients([], [
            'cty' => 'JWT',
        ])];
    }

    /**
     * The issuer did not mark the token as a nested token, and the token is refused. The "unprotected" member is not
     * covered by the authentication tag: adding one takes no key, and the token then loads.
     */
    #[Test]
    public function aContentTypeAddedToAnIssuedTokenIsDeprecated(): void
    {
        $issued = self::encrypt(new JSONFlattenedSerializer());
        $data = JsonConverter::decode($issued);
        static::assertIsArray($data);
        $tampered = JsonConverter::encode([
            ...$data,
            'unprotected' => [
                'cty' => 'JWT',
            ],
        ]);

        $error = $this->loadingError($issued);
        $deprecations = $this->collectDeprecations(static function () use ($tampered): void {
            static::assertSame(self::CLAIMS, self::load($tampered)->getPayload());
        });

        static::assertInstanceOf(InvalidArgumentException::class, $error);
        static::assertSame('The token is not a nested token.', $error->getMessage());
        static::assertCount(1, $deprecations);
    }

    /**
     * @param class-string<Throwable> $exception
     */
    #[Test]
    #[DataProvider('refusedTokens')]
    public function theseTokensAreStillRefusedWithoutDeprecation(string $token, string $exception, string $message): void
    {
        $error = null;
        $deprecations = $this->collectDeprecations(function () use ($token, &$error): void {
            $error = $this->loadingError($token);
        });

        static::assertInstanceOf(Throwable::class, $error);
        static::assertSame([$exception, $message], [$error::class, $error->getMessage()]);
        static::assertSame([], $deprecations);
    }

    /**
     * @return iterable<string, array{string, class-string<Throwable>, string}>
     */
    public static function refusedTokens(): iterable
    {
        yield 'no "cty"' => [
            self::encrypt(new JWECompactSerializer()),
            InvalidArgumentException::class,
            'The token is not a nested token.',
        ];
        yield 'no "cty", JSON general' => [
            self::encrypt(new JSONGeneralSerializer()),
            InvalidArgumentException::class,
            'The token is not a nested token.',
        ];
        yield 'another content type in the protected header' => [
            self::encrypt(new JWECompactSerializer(), [
                'cty' => 'text/plain',
            ]),
            InvalidArgumentException::class,
            'The token is not a nested token.',
        ];
        yield 'another content type in the shared unprotected header' => [
            self::encrypt(new JSONFlattenedSerializer(), [], [
                'cty' => 'text/plain',
            ]),
            InvalidArgumentException::class,
            'The token is not a nested token.',
        ];
        yield 'a protected "cty" that is not a string' => [
            self::encrypt(new JWECompactSerializer(), [
                'cty' => 42,
            ]),
            InvalidHeaderParameterException::class,
            'Invalid "cty" header parameter.',
        ];
        yield 'an unprotected "cty" that is not a string' => [
            self::encrypt(new JSONFlattenedSerializer(), [], [
                'cty' => 42,
            ]),
            InvalidHeaderParameterException::class,
            'Invalid "cty" header parameter.',
        ];
        yield '"cty" in the header of a recipient that is not decrypted' => [
            self::encryptForTwoRecipients([
                'cty' => 'JWT',
            ], []),
            InvalidArgumentException::class,
            'The token is not a nested token.',
        ];
        yield 'an unprotected "cty" around a JWS that does not verify' => [
            self::encrypt(new JSONFlattenedSerializer(), [], [
                'cty' => 'JWT',
            ], [], self::OTHER_SIGNATURE_KEY),
            InvalidTokenException::class,
            'Unable to load and verify the token.',
        ];
    }

    private static function load(string $token): JWS
    {
        return self::loader()
            ->loadAndVerify(
                $token,
                new JWKSet([self::octetKey(self::ENCRYPTION_KEY)]),
                new JWKSet([self::octetKey(self::SIGNATURE_KEY)])
            )
            ->getJws();
    }

    private function loadingError(string $token): ?Throwable
    {
        try {
            self::load($token);
        } catch (Throwable $throwable) {
            return $throwable;
        }

        return null;
    }

    /**
     * @param array<string, mixed> $protectedHeader
     * @param array<string, mixed> $sharedHeader
     * @param array<string, mixed> $recipientHeader
     */
    private static function encrypt(
        JWESerializer $serializer,
        array $protectedHeader = [],
        array $sharedHeader = [],
        array $recipientHeader = [],
        string $signatureKey = self::SIGNATURE_KEY
    ): string {
        $jwe = self::jweBuilder()
            ->withPayload(self::sign($signatureKey))
            ->withSharedProtectedHeader([
                'alg' => 'A128KW',
                'enc' => 'A128GCM',
                ...$protectedHeader,
            ])
            ->withSharedHeader($sharedHeader)
            ->addRecipient(self::octetKey(self::ENCRYPTION_KEY), $recipientHeader)
            ->build();

        return $serializer->serialize($jwe, 0);
    }

    /**
     * Only the second recipient is encrypted with the key of the application.
     *
     * @param array<string, mixed> $firstRecipientHeader
     * @param array<string, mixed> $secondRecipientHeader
     */
    private static function encryptForTwoRecipients(array $firstRecipientHeader, array $secondRecipientHeader): string
    {
        $jwe = self::jweBuilder()
            ->withPayload(self::sign(self::SIGNATURE_KEY))
            ->withSharedProtectedHeader([
                'alg' => 'A128KW',
                'enc' => 'A128GCM',
            ])
            ->addRecipient(self::octetKey(self::OTHER_ENCRYPTION_KEY), $firstRecipientHeader)
            ->addRecipient(self::octetKey(self::ENCRYPTION_KEY), $secondRecipientHeader)
            ->build();

        return (new JSONGeneralSerializer())->serialize($jwe);
    }

    private static function sign(string $signatureKey): string
    {
        $jws = (new JWSBuilder(new AlgorithmManager([new HS256()])))
            ->create()
            ->withPayload(self::CLAIMS)
            ->addSignature(self::octetKey($signatureKey), [
                'alg' => 'HS256',
            ])
            ->build();

        return (new CompactSerializer())->serialize($jws, 0);
    }

    private static function jweBuilder(): JWEBuilder
    {
        return (new JWEBuilder(new AlgorithmManager([new A128KW(), new A128GCM()])))->create();
    }

    private static function loader(): NestedTokenLoader
    {
        return new NestedTokenLoader(
            new JWELoader(
                new JWESerializerManager([
                    new JWECompactSerializer(),
                    new JSONFlattenedSerializer(),
                    new JSONGeneralSerializer(),
                ]),
                new JWEDecrypter(new AlgorithmManager([new A128KW(), new A128GCM()])),
                null
            ),
            new JWSLoader(
                new JWSSerializerManager([new CompactSerializer()]),
                new JWSVerifier(new AlgorithmManager([new HS256()])),
                null
            )
        );
    }

    private static function octetKey(string $secret): JWK
    {
        return new JWK([
            'kty' => 'oct',
            'k' => Base64UrlSafe::encodeUnpadded($secret),
        ]);
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
}
