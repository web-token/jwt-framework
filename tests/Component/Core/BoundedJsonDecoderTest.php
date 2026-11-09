<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Core;

use InvalidArgumentException;
use Jose\Component\Core\Exception\JsonBoundExceededException;
use Jose\Component\Core\Util\BoundedJsonDecoder;
use JsonException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function intdiv;
use function str_repeat;
use const JSON_ERROR_DEPTH;
use const JSON_ERROR_SYNTAX;

/**
 * @internal
 */
final class BoundedJsonDecoderTest extends TestCase
{
    private const TOO_MANY_VALUES = 'The JSON documents of the token hold more JSON values than the 4096 that are decoded.';

    private const TOO_DEEP = 'A JSON document of the token is nested too deeply.';

    #[Test]
    public function aDocumentAtTheBoundIsDecoded(): void
    {
        $document = '[' . str_repeat('0,', BoundedJsonDecoder::MAX_VALUES - 1) . '0]';

        static::assertCount(BoundedJsonDecoder::MAX_VALUES, (new BoundedJsonDecoder())->decode($document));
    }

    #[Test]
    public function aDocumentBeyondTheBoundIsRejectedBeforeItIsDecoded(): void
    {
        $document = '[' . str_repeat('0,', BoundedJsonDecoder::MAX_VALUES) . '0]';

        try {
            (new BoundedJsonDecoder())->decode($document);
            static::fail('The document should have been rejected.');
        } catch (InvalidArgumentException $e) {
            static::assertSame(self::TOO_MANY_VALUES, $e->getMessage());
            static::assertNull($e->getPrevious());
        }
    }

    #[Test]
    public function theBoundIsExceededOnceADocumentIsRejectedForTheValuesItHolds(): void
    {
        $json = new BoundedJsonDecoder();
        $json->decode('[' . str_repeat('0,', BoundedJsonDecoder::MAX_VALUES - 1) . '0]');

        static::assertFalse($json->hasExceededMaxValues());

        try {
            $json->decode('[]');
            static::fail('The document should have been rejected.');
        } catch (InvalidArgumentException) {
        }

        static::assertTrue($json->hasExceededMaxValues());
        static::assertFalse($json->hasExceededMaxDepth());
    }

    /**
     * The decoder names the bound and keeps the code and the error of json_decode().
     */
    #[Test]
    public function aDocumentNestedTooDeeplyIsRejectedForItsDepth(): void
    {
        $json = new BoundedJsonDecoder();
        $json->decode('[[0]]');

        static::assertFalse($json->hasExceededMaxDepth());

        try {
            $json->decode(str_repeat('[', 600) . str_repeat(']', 600));
            static::fail('The document should have been rejected.');
        } catch (InvalidArgumentException $e) {
            static::assertSame(self::TOO_DEEP, $e->getMessage());
            static::assertSame(JSON_ERROR_DEPTH, $e->getCode());
            static::assertInstanceOf(JsonException::class, $e->getPrevious());
            static::assertSame('Maximum stack depth exceeded', $e->getPrevious()->getMessage());
        }

        static::assertTrue($json->hasExceededMaxDepth());
        static::assertFalse($json->hasExceededMaxValues());
    }

    #[Test]
    public function anInvalidDocumentKeepsTheErrorOfTheJsonConverter(): void
    {
        $json = new BoundedJsonDecoder();

        try {
            $json->decode('[0,');
            static::fail('The document should have been rejected.');
        } catch (InvalidArgumentException $e) {
            static::assertSame('Unsupported input.', $e->getMessage());
            static::assertSame(JSON_ERROR_SYNTAX, $e->getCode());
            static::assertNotInstanceOf(JsonBoundExceededException::class, $e);
        }

        static::assertFalse($json->hasExceededMaxDepth());
        static::assertFalse($json->hasExceededMaxValues());
    }

    /**
     * The class of the exception tells the two bounds apart from invalid JSON, whatever its message.
     */
    #[Test]
    #[DataProvider('documentsBeyondABound')]
    public function aDocumentBeyondABoundIsRejectedWithAJsonBoundExceededException(string $document): void
    {
        $this->expectException(JsonBoundExceededException::class);

        (new BoundedJsonDecoder())->decode($document);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function documentsBeyondABound(): iterable
    {
        yield 'more than 4096 values' => ['[' . str_repeat('0,', BoundedJsonDecoder::MAX_VALUES) . '0]'];
        yield 'nested too deeply' => [str_repeat('[', 600) . str_repeat(']', 600)];
    }

    #[Test]
    #[DataProvider('documentsJsonDecodeRejects')]
    public function aDocumentJsonDecodeRejectsDoesNotExceedTheBound(string $document): void
    {
        $json = new BoundedJsonDecoder();

        try {
            $json->decode($document);
            static::fail('The document should have been rejected.');
        } catch (InvalidArgumentException) {
        }

        static::assertFalse($json->hasExceededMaxValues());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function documentsJsonDecodeRejects(): iterable
    {
        yield 'invalid JSON' => ['[0,'];
        yield 'nested too deeply' => [str_repeat('[', 600) . str_repeat(']', 600)];
    }

    #[Test]
    public function nestedContainersAreCounted(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(self::TOO_MANY_VALUES);

        $group = str_repeat('[', 100) . str_repeat(']', 100);
        (new BoundedJsonDecoder())->decode('{"x":[' . str_repeat($group . ',', 41) . '0]}');
    }

    #[Test]
    public function theContentOfStringsIsNotCounted(): void
    {
        $document = '{"text":"' . str_repeat('[{,\"\\\\', BoundedJsonDecoder::MAX_VALUES) . '"}';

        static::assertSame([
            'text' => str_repeat('[{,"\\', BoundedJsonDecoder::MAX_VALUES),
        ], (new BoundedJsonDecoder())->decode($document));
    }

    /**
     * The first string holds one escaped backslash: the quote that follows it ends the string, so the array after it
     * has to be counted.
     */
    #[Test]
    public function aStringEndingWithAnEscapedBackslashDoesNotHideTheValuesThatFollowIt(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(self::TOO_MANY_VALUES);

        (new BoundedJsonDecoder())->decode(
            '["\\\\",[' . str_repeat('0,', BoundedJsonDecoder::MAX_VALUES) . '0],"\\\\"]'
        );
    }

    #[Test]
    public function theDocumentsOfOneTokenShareTheBound(): void
    {
        $half = intdiv(BoundedJsonDecoder::MAX_VALUES, 2);
        $document = '[' . str_repeat('0,', $half - 1) . '0]';
        $json = new BoundedJsonDecoder();
        $json->decode($document);
        $json->decode($document);

        static::assertCount($half, (new BoundedJsonDecoder())->decode($document));
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(self::TOO_MANY_VALUES);

        $json->decode('[]');
    }
}
