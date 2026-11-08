<?php

declare(strict_types=1);

namespace Jose\Tests\Component\NestedToken;

use Jose\Component\Checker\HeaderCheckerManagerFactory;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\AlgorithmManagerFactory;
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
use Jose\Component\Encryption\JWEDecrypterFactory;
use Jose\Component\Encryption\JWELoader;
use Jose\Component\Encryption\JWELoaderFactory;
use Jose\Component\Encryption\JWETokenSupport;
use Jose\Component\Encryption\Serializer\CompactSerializer as JWECompactSerializer;
use Jose\Component\Encryption\Serializer\JSONFlattenedSerializer;
use Jose\Component\Encryption\Serializer\JSONGeneralSerializer;
use Jose\Component\Encryption\Serializer\JWESerializer;
use Jose\Component\Encryption\Serializer\JWESerializerManager;
use Jose\Component\Encryption\Serializer\JWESerializerManagerFactory;
use Jose\Component\NestedToken\NestedTokenLoader;
use Jose\Component\NestedToken\NestedTokenLoaderFactory;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWSLoader;
use Jose\Component\Signature\JWSLoaderFactory;
use Jose\Component\Signature\JWSTokenSupport;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\JWSVerifierFactory;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use Jose\Component\Signature\Serializer\JWSSerializerManagerFactory;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Throwable;
use function sprintf;
use const E_USER_DEPRECATED;

/**
 * A JWE carries a nested token when its "cty" header parameter is "JWT". The authentication tag covers the protected
 * header only: a "cty" in the shared unprotected header or in a recipient header of a JSON serialization can be added
 * to a token without any key. The third argument of the loader sets what happens to such a token: true loads it, false
 * refuses it. Without that argument, or with null, the token loads with a deprecation, as 5.0.0 refuses it by default.
 *
 * Each policy is written as the list of the arguments passed after the two loaders, so that passing no third argument
 * at all is tested as well as passing null.
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

    private const DEPRECATION = 'Since web-token/jwt-library 4.3.0: Loading a nested token whose "cty" header parameter is not in the protected header is deprecated and "%s" will refuse such a token by default in 5.0.0, as the unprotected headers of a JWE are not authenticated. Have the issuer set "cty" in the protected header, or pass true as the third argument of the constructor to keep loading these tokens, or false to refuse them. With the bundle, set the "allow_unprotected_content_type" option of the nested token loader.';

    private const REFUSAL = 'The "cty" header parameter must be in the protected header.';

    /**
     * @param list<bool|null> $policy
     */
    #[Test]
    #[DataProvider('protectedContentTypesAndPolicies')]
    public function aTokenMarkedInTheProtectedHeaderLoadsWithoutDeprecation(string $token, array $policy): void
    {
        $deprecations = $this->collectDeprecations(static function () use ($token, $policy): void {
            static::assertSame(self::CLAIMS, self::load($token, $policy)->getPayload());
        });

        static::assertSame([], $deprecations);
    }

    /**
     * @return iterable<string, array{string, list<bool|null>}>
     */
    public static function protectedContentTypesAndPolicies(): iterable
    {
        foreach (self::protectedContentTypes() as $name => $token) {
            foreach (self::policies() as $policyName => $policy) {
                yield sprintf('%s, %s', $name, $policyName) => [$token, $policy];
            }
        }
    }

    /**
     * Without the third argument, or with null, a "cty" outside the protected header still marks a nested token: the
     * token loads as before, with a deprecation.
     *
     * @param list<bool|null> $policy
     */
    #[Test]
    #[DataProvider('unprotectedContentTypesAndDefaultPolicies')]
    public function aTokenMarkedOutsideTheProtectedHeaderIsDeprecatedByDefault(string $token, array $policy): void
    {
        $deprecations = $this->collectDeprecations(static function () use ($token, $policy): void {
            static::assertSame(self::CLAIMS, self::load($token, $policy)->getPayload());
        });

        static::assertSame([sprintf(self::DEPRECATION, NestedTokenLoader::class)], $deprecations);
    }

    /**
     * @return iterable<string, array{string, list<bool|null>}>
     */
    public static function unprotectedContentTypesAndDefaultPolicies(): iterable
    {
        foreach (self::unprotectedContentTypes() as $name => $token) {
            yield sprintf('%s, no argument', $name) => [$token, []];
            yield sprintf('%s, null', $name) => [$token, [null]];
        }
    }

    #[Test]
    #[DataProvider('unprotectedContentTypesAlone')]
    public function aTokenMarkedOutsideTheProtectedHeaderLoadsWithoutDeprecationWhenAllowed(string $token): void
    {
        $deprecations = $this->collectDeprecations(static function () use ($token): void {
            static::assertSame(self::CLAIMS, self::load($token, [true])->getPayload());
        });

        static::assertSame([], $deprecations);
    }

    /**
     * The token is refused before its payload is read.
     */
    #[Test]
    #[DataProvider('unprotectedContentTypesAlone')]
    public function aTokenMarkedOutsideTheProtectedHeaderIsRefusedWhenNotAllowed(string $token): void
    {
        $error = null;
        $deprecations = $this->collectDeprecations(function () use ($token, &$error): void {
            $error = $this->loadingError($token, [false]);
        });

        static::assertInstanceOf(Throwable::class, $error);
        static::assertSame(
            [InvalidHeaderParameterException::class, self::REFUSAL],
            [$error::class, $error->getMessage()]
        );
        static::assertSame([], $deprecations);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function unprotectedContentTypesAlone(): iterable
    {
        foreach (self::unprotectedContentTypes() as $name => $token) {
            yield $name => [$token];
        }
    }

    /**
     * The issuer did not mark the token as a nested token, and the token is refused. The "unprotected" member is not
     * covered by the authentication tag: adding one takes no key, and the token then loads.
     */
    #[Test]
    public function aContentTypeAddedToAnIssuedTokenIsDeprecated(): void
    {
        $issued = self::encrypt(new JSONFlattenedSerializer());
        $tampered = self::addUnprotectedContentType($issued);

        $error = $this->loadingError($issued, []);
        $deprecations = $this->collectDeprecations(static function () use ($tampered): void {
            static::assertSame(self::CLAIMS, self::load($tampered, [])->getPayload());
        });

        static::assertInstanceOf(InvalidArgumentException::class, $error);
        static::assertSame('The token is not a nested token.', $error->getMessage());
        static::assertSame([sprintf(self::DEPRECATION, NestedTokenLoader::class)], $deprecations);
    }

    #[Test]
    public function aContentTypeAddedToAnIssuedTokenIsRefusedWhenNotAllowed(): void
    {
        $tampered = self::addUnprotectedContentType(self::encrypt(new JSONFlattenedSerializer()));

        $error = $this->loadingError($tampered, [false]);

        static::assertInstanceOf(InvalidHeaderParameterException::class, $error);
        static::assertSame(self::REFUSAL, $error->getMessage());
    }

    /**
     * @param class-string<Throwable> $exception
     * @param list<bool|null> $policy
     */
    #[Test]
    #[DataProvider('refusedTokensAndPolicies')]
    public function theseTokensAreStillRefusedWithoutDeprecation(
        string $token,
        string $exception,
        string $message,
        array $policy
    ): void {
        $error = null;
        $deprecations = $this->collectDeprecations(function () use ($token, $policy, &$error): void {
            $error = $this->loadingError($token, $policy);
        });

        static::assertInstanceOf(Throwable::class, $error);
        static::assertSame([$exception, $message], [$error::class, $error->getMessage()]);
        static::assertSame([], $deprecations);
    }

    /**
     * A token refused today is refused with the same exception whatever the policy, except a token marked outside the
     * protected header around a JWS that does not verify: false refuses it before the JWS is verified.
     *
     * @return iterable<string, array{string, class-string<Throwable>, string, list<bool|null>}>
     */
    public static function refusedTokensAndPolicies(): iterable
    {
        foreach (self::refusedTokens() as $name => [$token, $exception, $message]) {
            foreach (self::policies() as $policyName => $policy) {
                yield sprintf('%s, %s', $name, $policyName) => [$token, $exception, $message, $policy];
            }
        }
        $unverified = self::encrypt(new JSONFlattenedSerializer(), [], [
            'cty' => 'JWT',
        ], [], self::OTHER_SIGNATURE_KEY);
        foreach (self::policies() as $policyName => $policy) {
            yield sprintf('an unprotected "cty" around a JWS that does not verify, %s', $policyName) => $policy === [false]
                ? [$unverified, InvalidHeaderParameterException::class, self::REFUSAL, $policy]
                : [$unverified, InvalidTokenException::class, 'Unable to load and verify the token.', $policy];
        }
    }

    #[Test]
    #[DataProvider('invalidPolicies')]
    public function aPolicyThatIsNotABooleanIsRejected(mixed $policy): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'The policy for a "cty" header parameter outside the protected header must be a boolean: true accepts it, false refuses it.'
        );

        self::loader([$policy]);
    }

    /**
     * @return iterable<string, array{mixed}>
     */
    public static function invalidPolicies(): iterable
    {
        yield 'string' => ['false'];
        yield 'zero' => [0];
        yield 'one' => [1];
        yield 'array' => [[]];
    }

    /**
     * The seventh argument of the factory is passed to the loader it creates.
     *
     * @param list<bool|null> $policy
     * @param list<string> $expectedDeprecations
     */
    #[Test]
    #[DataProvider('factoryPolicies')]
    public function theLoaderFactoryPassesThePolicyToTheLoader(
        array $policy,
        array $expectedDeprecations,
        ?string $expectedError
    ): void {
        $loader = self::loaderFactory()->create(
            ['jwe_json_flattened'],
            ['A128KW', 'A128GCM'],
            [],
            ['jws_compact'],
            ['HS256'],
            [],
            ...$policy
        );
        $token = self::encrypt(new JSONFlattenedSerializer(), [], [
            'cty' => 'JWT',
        ]);

        $error = null;
        $deprecations = $this->collectDeprecations(function () use ($loader, $token, &$error): void {
            $error = $this->loadingErrorWith($loader, $token)?->getMessage();
        });

        static::assertSame([$expectedDeprecations, $expectedError], [$deprecations, $error]);
    }

    /**
     * @return iterable<string, array{list<bool|null>, list<string>, string|null}>
     */
    public static function factoryPolicies(): iterable
    {
        $deprecation = sprintf(self::DEPRECATION, NestedTokenLoader::class);
        yield 'no argument' => [[], [$deprecation], null];
        yield 'null' => [[null], [$deprecation], null];
        yield 'true' => [[true], [], null];
        yield 'false' => [[false], [], self::REFUSAL];
    }

    /**
     * @return array<string, list<bool|null>>
     */
    private static function policies(): array
    {
        return [
            'no argument' => [],
            'null' => [null],
            'true' => [true],
            'false' => [false],
        ];
    }

    /**
     * @return iterable<string, string>
     */
    private static function protectedContentTypes(): iterable
    {
        yield 'compact' => self::encrypt(new JWECompactSerializer(), [
            'cty' => 'JWT',
        ]);
        yield 'JSON flattened' => self::encrypt(new JSONFlattenedSerializer(), [
            'cty' => 'JWT',
        ]);
        yield 'JSON general' => self::encrypt(new JSONGeneralSerializer(), [
            'cty' => 'JWT',
        ]);
        yield 'lower case' => self::encrypt(new JWECompactSerializer(), [
            'cty' => 'jwt',
        ]);
        yield 'next to unprotected header parameters' => self::encrypt(new JSONGeneralSerializer(), [
            'cty' => 'JWT',
        ], [
            'x-shared' => 'shared',
        ], [
            'x-recipient' => 'recipient',
        ]);
    }

    /**
     * @return iterable<string, string>
     */
    private static function unprotectedContentTypes(): iterable
    {
        yield 'shared unprotected header, JSON flattened' => self::encrypt(new JSONFlattenedSerializer(), [], [
            'cty' => 'JWT',
        ]);
        yield 'recipient header, JSON flattened' => self::encrypt(new JSONFlattenedSerializer(), [], [], [
            'cty' => 'JWT',
        ]);
        yield 'shared unprotected header, JSON general' => self::encrypt(new JSONGeneralSerializer(), [], [
            'cty' => 'JWT',
        ]);
        yield 'recipient header, JSON general' => self::encrypt(new JSONGeneralSerializer(), [], [], [
            'cty' => 'JWT',
        ]);
        yield 'lower case' => self::encrypt(new JSONFlattenedSerializer(), [], [
            'cty' => 'jwt',
        ]);
        yield 'header of the decrypted recipient' => self::encryptForTwoRecipients([], [
            'cty' => 'JWT',
        ]);
    }

    /**
     * @return iterable<string, array{string, class-string<Throwable>, string}>
     */
    private static function refusedTokens(): iterable
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
    }

    /**
     * @param list<mixed> $policy
     */
    private static function load(string $token, array $policy): JWS
    {
        return self::loadWith(self::loader($policy), $token);
    }

    private static function loadWith(NestedTokenLoader $loader, string $token): JWS
    {
        return $loader
            ->loadAndVerify(
                $token,
                new JWKSet([self::octetKey(self::ENCRYPTION_KEY)]),
                new JWKSet([self::octetKey(self::SIGNATURE_KEY)])
            )
            ->getJws();
    }

    /**
     * @param list<mixed> $policy
     */
    private function loadingError(string $token, array $policy): ?Throwable
    {
        return $this->loadingErrorWith(self::loader($policy), $token);
    }

    private function loadingErrorWith(NestedTokenLoader $loader, string $token): ?Throwable
    {
        try {
            self::loadWith($loader, $token);
        } catch (Throwable $throwable) {
            return $throwable;
        }

        return null;
    }

    private static function addUnprotectedContentType(string $token): string
    {
        $data = JsonConverter::decode($token);
        static::assertIsArray($data);

        return JsonConverter::encode([
            ...$data,
            'unprotected' => [
                'cty' => 'JWT',
            ],
        ]);
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
            ->withPayload(self::CLAIMS)
            ->addSignature(self::octetKey($signatureKey), [
                'alg' => 'HS256',
            ])
            ->build();

        return (new CompactSerializer())->serialize($jws, 0);
    }

    private static function jweBuilder(): JWEBuilder
    {
        return new JWEBuilder(new AlgorithmManager([new A128KW(), new A128GCM()]));
    }

    /**
     * @param list<mixed> $policy the arguments passed after the two loaders
     */
    private static function loader(array $policy): NestedTokenLoader
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
            ),
            ...$policy
        );
    }

    private static function loaderFactory(): NestedTokenLoaderFactory
    {
        $algorithms = new AlgorithmManagerFactory([new A128KW(), new A128GCM(), new HS256()]);
        $jweSerializers = new JWESerializerManagerFactory();
        $jweSerializers->add(new JSONFlattenedSerializer());
        $jwsSerializers = new JWSSerializerManagerFactory();
        $jwsSerializers->add(new CompactSerializer());
        $jweHeaderCheckers = new HeaderCheckerManagerFactory();
        $jweHeaderCheckers->addTokenTypeSupport(new JWETokenSupport());
        $jwsHeaderCheckers = new HeaderCheckerManagerFactory();
        $jwsHeaderCheckers->addTokenTypeSupport(new JWSTokenSupport());

        return new NestedTokenLoaderFactory(
            new JWELoaderFactory($jweSerializers, new JWEDecrypterFactory($algorithms), $jweHeaderCheckers),
            new JWSLoaderFactory($jwsSerializers, new JWSVerifierFactory($algorithms), $jwsHeaderCheckers)
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
