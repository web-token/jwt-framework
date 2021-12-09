<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Core;

use Jose\Component\Core\Util\JsonConverter;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
final class JsonConverterTest extends TestCase
{
    /**
     * @test
     */
    public function iCanConvertAnObjectIntoAJsonString(): void
    {
        static::assertSame('{"foo":"BAR"}', JsonConverter::encode([
            'foo' => 'BAR',
        ]));
        static::assertSame([
            'foo' => 'BAR',
        ], JsonConverter::decode('{"foo":"BAR"}'));
    }
}
