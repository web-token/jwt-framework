<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Core;

use InvalidArgumentException;
use Jose\Component\Core\Util\BoundedJsonDecoder;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function intdiv;
use function str_repeat;

/**
 * @internal
 */
final class BoundedJsonDecoderTest extends TestCase
{
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
            static::assertSame('Unsupported input.', $e->getMessage());
            static::assertNull($e->getPrevious());
        }
    }

    #[Test]
    public function nestedContainersAreCounted(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Unsupported input.');

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
        $this->expectExceptionMessage('Unsupported input.');

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
        $this->expectExceptionMessage('Unsupported input.');

        $json->decode('[]');
    }
}
