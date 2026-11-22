<?php

declare(strict_types=1);

namespace Jose\Tests\Component\KeyManagement;

use Jose\Component\Core\Exception\InvalidArgumentException;
use Jose\Component\Core\Exception\JsonBoundExceededException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\JKUFactory;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\KeyManagement\X5UFactory;
use Jose\Tests\Component\Core\ExceptionTraceArgumentsTrait;
use JsonException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;
use Throwable;
use function file_get_contents;
use function json_encode;
use function restore_error_handler;
use function set_error_handler;
use function sprintf;
use function str_repeat;
use const E_USER_DEPRECATED;
use const JSON_ERROR_SYNTAX;
use const JSON_THROW_ON_ERROR;

/**
 * JWKFactory::fromJsonObject() and the factories of the key sets of a URL bound the JSON values they decode: a document
 * of more than 4096 values is decoded with a deprecation, as 5.0.0 refuses it by default, unless the caller chooses.
 *
 * @internal
 */
final class LargeJsonDocumentTest extends TestCase
{
    use ExceptionTraceArgumentsTrait;

    private const URL = 'https://keys.example.com/jwks';

    private const DEPRECATION = 'Since web-token/jwt-framework 4.3.0: Decoding a JSON document of more than 4096 values is deprecated and "Jose\Component\KeyManagement\JWKFactory::fromJsonObject()" will refuse it by default in 5.0.0. Pass true as the second argument to keep decoding it, or false to refuse it now.';

    private const URL_DEPRECATION = 'Since web-token/jwt-framework 4.3.0: Loading a key set of more than 4096 JSON values is deprecated and "%s" will refuse it by default in 5.0.0. Pass true as the third argument of the constructor to keep loading it, or false to refuse it now. With the bundle, set the "jose.jku_factory.allow_large_key_sets" option.';

    private const REFUSED = 'The JSON document holds more JSON values than the 4096 that are decoded.';

    private const SECRET = 'GawgguFyGrWKav7AX4VKUg';

    /**
     * @param list<mixed> $arguments
     */
    #[Test]
    #[DataProvider('bounds')]
    public function theValuesOfAJsonObjectAreBoundedAsTheSecondArgumentSays(
        array $arguments,
        int $values,
        string $outcome
    ): void {
        $document = '{"kty":"oct","k":"AAAA","x":' . self::values($values - 3) . '}';
        $created = null;
        $exception = null;
        $deprecations = self::collectDeprecations(static function () use (
            $document,
            $arguments,
            &$created,
            &$exception
        ): void {
            try {
                $created = (new JWKFactory())->fromJsonObject($document, ...$arguments);
            } catch (InvalidArgumentException $failure) {
                $exception = $failure;
            }
        });

        static::assertSame($outcome === 'deprecated' ? [self::DEPRECATION] : [], $deprecations);
        match ($outcome) {
            'created', 'deprecated' => static::assertInstanceOf(JWK::class, $created),
            'refused' => static::assertSame([JsonBoundExceededException::class, self::REFUSED], [
                $exception::class,
                $exception->getMessage(),
            ]),
            'invalid argument' => static::assertSame(
                'The second argument of "Jose\Component\KeyManagement\JWKFactory::fromJsonObject()" must be a boolean: true decodes a document of any number of values, false refuses one of more than 4096.',
                $exception->getMessage()
            ),
        };
    }

    #[Test]
    public function theDepthOfAJsonObjectIsBoundedByJsonDecode(): void
    {
        static::assertInstanceOf(
            JWK::class,
            (new JWKFactory())->fromJsonObject('{"kty":"oct","k":"AAAA","x":' . self::arrays(510) . '}')
        );

        $this->expectException(JsonException::class);
        $this->expectExceptionMessage('Maximum stack depth exceeded');

        (new JWKFactory())->fromJsonObject('{"kty":"oct","k":"AAAA","x":' . self::arrays(511) . '}');
    }

    /**
     * The deprecated static factory passes its second argument on.
     */
    #[Test]
    public function theDeprecatedStaticFactoryPassesTheSecondArgumentOn(): void
    {
        $exception = null;
        self::collectDeprecations(static function () use (&$exception): void {
            try {
                JWKFactory::createFromJsonObject('{"kty":"oct","k":"AAAA","x":' . self::values(4094) . '}', false);
            } catch (JsonBoundExceededException $failure) {
                $exception = $failure;
            }
        });

        static::assertInstanceOf(JsonBoundExceededException::class, $exception);
    }

    #[Test]
    public function anInvalidJsonObjectKeepsItsJsonExceptionWithoutTheKey(): void
    {
        $exception = self::failureOf(
            static fn (): JWK|JWKSet => (new JWKFactory())->fromJsonObject('{"kty":"oct","k":"' . self::SECRET . '"')
        );

        static::assertSame([JsonException::class, 'Syntax error', JSON_ERROR_SYNTAX], [
            $exception::class,
            $exception->getMessage(),
            $exception->getCode(),
        ]);
        static::assertTrue(self::argumentsAreRecorded($exception));
        static::assertSame([], self::callsHolding($exception, self::SECRET));
    }

    /**
     * A key set of a URL is decoded with a deprecation when the factory has no policy for large key sets.
     *
     * @param class-string<JKUFactory|X5UFactory> $factory
     * @param list<mixed> $policy
     */
    #[Test]
    #[DataProvider('largeKeySetPolicies')]
    public function aLargeKeySetOfAUrlIsLoadedAsThePolicySays(string $factory, array $policy, string $outcome): void
    {
        $instance = new $factory(self::client(self::largeDocument($factory)), ...$policy);
        $exception = null;
        $deprecations = self::collectDeprecations(static function () use ($instance, &$exception): void {
            try {
                $instance->loadFromUrl(self::URL);
            } catch (Throwable $failure) {
                $exception = $failure;
            }
        });

        static::assertSame($outcome === 'deprecated' ? [sprintf(self::URL_DEPRECATION, $factory)] : [], $deprecations);
        if ($outcome === 'refused') {
            static::assertInstanceOf(JsonBoundExceededException::class, $exception);
            static::assertSame(self::REFUSED, $exception->getMessage());
        } else {
            static::assertNotInstanceOf(JsonBoundExceededException::class, $exception);
        }
    }

    /**
     * @param class-string<JKUFactory|X5UFactory> $factory
     * @param list<mixed> $policy
     */
    #[Test]
    #[DataProvider('smallKeySetPolicies')]
    public function aKeySetWithinTheBoundIsLoadedSilently(string $factory, string $document, array $policy): void
    {
        $instance = new $factory(self::client($document), ...$policy);
        $keySet = null;
        $deprecations = self::collectDeprecations(static function () use ($instance, &$keySet): void {
            $keySet = $instance->loadFromUrl(self::URL);
        });

        static::assertSame([], $deprecations);
        static::assertInstanceOf(JWKSet::class, $keySet);
    }

    /**
     * @param class-string<JKUFactory|X5UFactory> $factory
     */
    #[Test]
    #[DataProvider('factories')]
    public function thePolicyForLargeKeySetsMustBeABoolean(string $factory): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'The policy for large key sets must be a boolean: true loads them, false refuses them.'
        );

        new $factory(self::client('{}'), null, 'false');
    }

    /**
     * @return iterable<string, array{list<mixed>, int, string}>
     */
    public static function bounds(): iterable
    {
        foreach ([
            'without a second argument' => [],
            'null' => [null],
            'true' => [true],
            'false' => [false],
        ] as $name => $arguments) {
            yield sprintf('%s, 4096 values', $name) => [$arguments, 4096, 'created'];
        }
        yield 'without a second argument, 4097 values' => [[], 4097, 'deprecated'];
        yield 'null, 4097 values' => [[null], 4097, 'deprecated'];
        yield 'true, 4097 values' => [[true], 4097, 'created'];
        yield 'false, 4097 values' => [[false], 4097, 'refused'];
        yield 'a string, 4096 values' => [['true'], 4096, 'invalid argument'];
    }

    /**
     * @return iterable<string, array{class-string<JKUFactory|X5UFactory>, list<mixed>, string}>
     */
    public static function largeKeySetPolicies(): iterable
    {
        foreach ([JKUFactory::class, X5UFactory::class] as $factory) {
            yield sprintf('%s, without a third argument', $factory) => [$factory, [], 'deprecated'];
            yield sprintf('%s, null', $factory) => [$factory, [null, null], 'deprecated'];
            yield sprintf('%s, true', $factory) => [$factory, [null, true], 'loaded'];
            yield sprintf('%s, false', $factory) => [$factory, [null, false], 'refused'];
        }
    }

    /**
     * @return iterable<string, array{class-string<JKUFactory|X5UFactory>, string, list<mixed>}>
     */
    public static function smallKeySetPolicies(): iterable
    {
        $documents = [
            JKUFactory::class => '{"keys":[{"kty":"oct","kid":"key","k":"dGFyZ2V0"}]}',
            X5UFactory::class => json_encode([
                'key' => file_get_contents(__DIR__ . '/RSA/PEM/2048b-rsa-example-cert.pem'),
            ], JSON_THROW_ON_ERROR),
        ];
        foreach ($documents as $factory => $document) {
            foreach ([
                'without a third argument' => [],
                'null' => [null, null],
                'true' => [null, true],
                'false' => [null, false],
            ] as $name => $policy) {
                yield sprintf('%s, %s', $factory, $name) => [$factory, $document, $policy];
            }
        }
    }

    /**
     * @return iterable<string, array{class-string<JKUFactory|X5UFactory>}>
     */
    public static function factories(): iterable
    {
        yield 'JKU' => [JKUFactory::class];
        yield 'X5U' => [X5UFactory::class];
    }

    /**
     * A document of 4097 values: a key set for JKUFactory, and an object of certificates for X5UFactory, whose array
     * of values is not a certificate.
     *
     * @param class-string<JKUFactory|X5UFactory> $factory
     */
    private static function largeDocument(string $factory): string
    {
        return $factory === JKUFactory::class
            ? '{"keys":[{"kty":"oct","k":"AAAA","x":' . self::values(4092) . '}]}'
            : '{"key":' . self::values(4096) . '}';
    }

    private static function arrays(int $levels): string
    {
        return str_repeat('[', $levels) . '0' . str_repeat(']', $levels);
    }

    private static function values(int $count): string
    {
        return '[' . str_repeat('0,', $count - 1) . '0]';
    }

    private static function client(string $document): MockHttpClient
    {
        return new MockHttpClient(static fn (): MockResponse => new MockResponse($document));
    }

    /**
     * @return list<string>
     */
    private static function collectDeprecations(callable $callback): array
    {
        $deprecations = [];
        set_error_handler(static function (int $type, string $message) use (&$deprecations): bool {
            $deprecations[] = $message;

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
