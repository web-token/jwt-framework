<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Core;

use Jose\Component\Core\Exception\InvalidArgumentException;
use Jose\Component\Core\Exception\JsonBoundExceededException;
use Jose\Component\Core\Util\JsonConverter;
use JsonException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function restore_error_handler;
use function set_error_handler;
use function sprintf;
use function str_repeat;
use const E_USER_DEPRECATED;
use const JSON_ERROR_CTRL_CHAR;
use const JSON_ERROR_DEPTH;
use const JSON_ERROR_SYNTAX;
use const JSON_ERROR_UTF8;

/**
 * @internal
 */
final class JsonConverterTest extends TestCase
{
    private const DEPRECATION = 'Since web-token/jwt-framework 4.3.0: Decoding a JSON document of more than 4096 values is deprecated and "Jose\Component\Core\Util\JsonConverter::decode()" will refuse it by default in 5.0.0. Pass true as the second argument to keep decoding it, or false to refuse it now.';

    private const REFUSED = 'The JSON document holds more JSON values than the 4096 that are decoded.';

    private const INVALID_ARGUMENT = 'The second argument of "Jose\Component\Core\Util\JsonConverter::decode()" must be a boolean: true decodes a document of any number of values, false refuses one of more than 4096.';

    #[Test]
    public function iCanConvertAnObjectIntoAJsonString(): void
    {
        static::assertSame('{"foo":"BAR"}', JsonConverter::encode([
            'foo' => 'BAR',
        ]));
        static::assertSame([
            'foo' => 'BAR',
        ], JsonConverter::decode('{"foo":"BAR"}'));
    }

    /**
     * The message names the error of json_decode(), whose exception is chained as a copy with its code.
     */
    #[Test]
    #[DataProvider('invalidDocuments')]
    public function anInvalidDocumentIsRejectedWithTheErrorOfJsonDecode(string $json, string $error, int $code): void
    {
        try {
            JsonConverter::decode($json);
            static::fail('The document should have been rejected.');
        } catch (InvalidArgumentException $exception) {
            static::assertSame(InvalidArgumentException::class, $exception::class);
            static::assertSame('The JSON document is not valid: ' . $error . '.', $exception->getMessage());
            static::assertSame($code, $exception->getCode());
            static::assertInstanceOf(JsonException::class, $exception->getPrevious());
            static::assertSame($error, $exception->getPrevious()->getMessage());
        }
    }

    #[Test]
    public function aDocumentNestedTooDeeplyIsRejectedForItsDepth(): void
    {
        $this->expectException(JsonBoundExceededException::class);
        $this->expectExceptionMessage('The JSON document is nested too deeply.');
        $this->expectExceptionCode(JSON_ERROR_DEPTH);

        JsonConverter::decode(str_repeat('[', 600) . str_repeat(']', 600));
    }

    /**
     * Without a second argument, or with null, a document of more than 4096 values is decoded with a deprecation, as
     * 5.0.0 refuses it by default. True decodes it silently, false refuses it.
     *
     * @param list<mixed> $arguments
     */
    #[Test]
    #[DataProvider('bounds')]
    public function theValuesOfADocumentAreBoundedAsTheSecondArgumentSays(
        array $arguments,
        int $values,
        string $outcome
    ): void {
        $document = '[' . str_repeat('0,', $values - 1) . '0]';
        $decoded = null;
        $exception = null;
        $deprecations = self::collectDeprecations(static function () use ($document, $arguments, &$decoded, &$exception): void {
            try {
                $decoded = JsonConverter::decode($document, ...$arguments);
            } catch (InvalidArgumentException $failure) {
                $exception = $failure;
            }
        });

        static::assertSame($outcome === 'deprecated' ? [self::DEPRECATION] : [], $deprecations);
        match ($outcome) {
            'decoded', 'deprecated' => static::assertCount($values, $decoded),
            'refused' => static::assertSame([JsonBoundExceededException::class, self::REFUSED, 0], [
                $exception::class,
                $exception->getMessage(),
                $exception->getCode(),
            ]),
            'invalid argument' => static::assertSame([InvalidArgumentException::class, self::INVALID_ARGUMENT], [
                $exception::class,
                $exception->getMessage(),
            ]),
        };
    }

    /**
     * @return iterable<string, array{string, string, int}>
     */
    public static function invalidDocuments(): iterable
    {
        yield 'syntax' => ['{', 'Syntax error', JSON_ERROR_SYNTAX];
        yield 'invalid UTF-8' => ["\"\xff\"", 'Malformed UTF-8 characters, possibly incorrectly encoded', JSON_ERROR_UTF8];
        yield 'control character' => ["\"\x01\"", 'Control character error, possibly incorrectly encoded', JSON_ERROR_CTRL_CHAR];
    }

    /**
     * @return iterable<string, array{list<mixed>, int, string}>
     */
    public static function bounds(): iterable
    {
        $arguments = [
            'without a second argument' => [],
            'null' => [null],
            'true' => [true],
            'false' => [false],
        ];
        foreach ($arguments as $name => $argument) {
            yield sprintf('%s, 4096 values', $name) => [$argument, 4096, 'decoded'];
        }
        yield 'without a second argument, 4097 values' => [[], 4097, 'deprecated'];
        yield 'null, 4097 values' => [[null], 4097, 'deprecated'];
        yield 'true, 4097 values' => [[true], 4097, 'decoded'];
        yield 'false, 4097 values' => [[false], 4097, 'refused'];
        yield 'a string, 4096 values' => [['false'], 4096, 'invalid argument'];
        yield 'an integer, 4097 values' => [[0], 4097, 'invalid argument'];
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
