<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Core;

use Jose\Component\Core\Exception\InvalidArgumentException;
use Jose\Component\Core\Exception\JsonBoundExceededException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use JsonException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function restore_error_handler;
use function set_error_handler;
use function sprintf;
use function str_repeat;
use const E_USER_DEPRECATED;
use const JSON_ERROR_SYNTAX;

/**
 * JWK::createFromJson() and JWKSet::createFromJson() bound the values of the document they decode as
 * JsonConverter::decode() does. They keep the JsonException of json_decode(), without the key in its trace.
 *
 * @internal
 */
final class KeyJsonDocumentTest extends TestCase
{
    use ExceptionTraceArgumentsTrait;

    private const DEPRECATION = 'Since web-token/jwt-framework 4.3.0: Decoding a JSON document of more than 4096 values is deprecated and "%s()" will refuse it by default in 5.0.0. Pass true as the second argument to keep decoding it, or false to refuse it now.';

    private const INVALID_ARGUMENT = 'The second argument of "%s()" must be a boolean: true decodes a document of any number of values, false refuses one of more than 4096.';

    private const REFUSED = 'The JSON document holds more JSON values than the 4096 that are decoded.';

    private const SECRET = 'GawgguFyGrWKav7AX4VKUg';

    /**
     * @param class-string<JWK|JWKSet> $class
     * @param list<mixed> $arguments
     */
    #[Test]
    #[DataProvider('bounds')]
    public function theValuesOfAKeyDocumentAreBoundedAsTheSecondArgumentSays(
        string $class,
        array $arguments,
        int $values,
        string $outcome
    ): void {
        $document = self::document($class, $values);
        $created = null;
        $exception = null;
        $deprecations = self::collectDeprecations(static function () use (
            $class,
            $document,
            $arguments,
            &$created,
            &$exception
        ): void {
            try {
                $created = $class::createFromJson($document, ...$arguments);
            } catch (InvalidArgumentException $failure) {
                $exception = $failure;
            }
        });

        $method = $class . '::createFromJson';
        static::assertSame($outcome === 'deprecated' ? [sprintf(self::DEPRECATION, $method)] : [], $deprecations);
        match ($outcome) {
            'created', 'deprecated' => static::assertInstanceOf($class, $created),
            'refused' => static::assertSame([JsonBoundExceededException::class, self::REFUSED], [
                $exception::class,
                $exception->getMessage(),
            ]),
            'invalid argument' => static::assertSame(
                [InvalidArgumentException::class, sprintf(self::INVALID_ARGUMENT, $method)],
                [$exception::class, $exception->getMessage()]
            ),
        };
    }

    /**
     * The exception of json_decode() records the document among the arguments of its trace, and the key would be
     * logged with it.
     *
     * @param class-string<JWK|JWKSet> $class
     */
    #[Test]
    #[DataProvider('documentsWithASecret')]
    public function anInvalidDocumentKeepsItsJsonExceptionWithoutTheKey(string $class, string $document): void
    {
        $exception = self::failureOf(static fn (): JWK|JWKSet => $class::createFromJson($document));

        static::assertSame([JsonException::class, 'Syntax error', JSON_ERROR_SYNTAX], [
            $exception::class,
            $exception->getMessage(),
            $exception->getCode(),
        ]);
        static::assertTrue(self::argumentsAreRecorded($exception));
        static::assertSame([], self::callsHolding($exception, self::SECRET));
    }

    /**
     * json_decode() reads 511 levels: a key of 512 levels is refused with its JsonException.
     *
     * @param class-string<JWK|JWKSet> $class
     */
    #[Test]
    #[DataProvider('depths')]
    public function theDepthOfAKeyDocumentIsBoundedByJsonDecode(string $class, string $document, bool $created): void
    {
        if (! $created) {
            $this->expectException(JsonException::class);
            $this->expectExceptionMessage('Maximum stack depth exceeded');
        }

        static::assertInstanceOf($class, $class::createFromJson($document));
    }

    /**
     * @return iterable<string, array{class-string<JWK|JWKSet>, string, bool}>
     */
    public static function depths(): iterable
    {
        yield 'JWK, 511 levels' => [JWK::class, '{"kty":"oct","k":"AAAA","x":' . self::arrays(510) . '}', true];
        yield 'JWK, 512 levels' => [JWK::class, '{"kty":"oct","k":"AAAA","x":' . self::arrays(511) . '}', false];
        yield 'JWKSet, 511 levels' => [
            JWKSet::class,
            '{"keys":[{"kty":"oct","k":"AAAA","x":' . self::arrays(508) . '}]}',
            true,
        ];
        yield 'JWKSet, 512 levels' => [
            JWKSet::class,
            '{"keys":[{"kty":"oct","k":"AAAA","x":' . self::arrays(509) . '}]}',
            false,
        ];
    }

    /**
     * @return iterable<string, array{class-string<JWK|JWKSet>, list<mixed>, int, string}>
     */
    public static function bounds(): iterable
    {
        foreach ([JWK::class, JWKSet::class] as $class) {
            foreach ([
                'without a second argument' => [],
                'null' => [null],
                'true' => [true],
                'false' => [false],
            ] as $name => $arguments) {
                yield sprintf('%s, %s, 4096 values', $class, $name) => [$class, $arguments, 4096, 'created'];
            }
            yield sprintf('%s, without a second argument, 4097 values', $class) => [$class, [], 4097, 'deprecated'];
            yield sprintf('%s, null, 4097 values', $class) => [$class, [null], 4097, 'deprecated'];
            yield sprintf('%s, true, 4097 values', $class) => [$class, [true], 4097, 'created'];
            yield sprintf('%s, false, 4097 values', $class) => [$class, [false], 4097, 'refused'];
            yield sprintf('%s, a string, 4096 values', $class) => [$class, ['true'], 4096, 'invalid argument'];
        }
    }

    /**
     * @return iterable<string, array{class-string<JWK|JWKSet>, string}>
     */
    public static function documentsWithASecret(): iterable
    {
        yield 'JWK' => [JWK::class, '{"kty":"oct","k":"' . self::SECRET . '"'];
        yield 'JWKSet' => [JWKSet::class, '{"keys":[{"kty":"oct","k":"' . self::SECRET . '"}]'];
    }

    /**
     * A key document of the given number of values: the array of the "x" member fills it.
     *
     * @param class-string<JWK|JWKSet> $class
     */
    private static function document(string $class, int $values): string
    {
        return $class === JWK::class
            ? '{"kty":"oct","k":"AAAA","x":' . self::values($values - 3) . '}'
            : '{"keys":[{"kty":"oct","k":"AAAA","x":' . self::values($values - 5) . '}]}';
    }

    private static function arrays(int $levels): string
    {
        return str_repeat('[', $levels) . '0' . str_repeat(']', $levels);
    }

    private static function values(int $count): string
    {
        return '[' . str_repeat('0,', $count - 1) . '0]';
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
