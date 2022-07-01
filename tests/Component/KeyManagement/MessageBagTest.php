<?php

declare(strict_types=1);

namespace Jose\Tests\Component\KeyManagement;

use function count;
use Jose\Component\KeyManagement\Analyzer\Message;
use Jose\Component\KeyManagement\Analyzer\MessageBag;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
final class MessageBagTest extends TestCase
{
    /**
     * @test
     */
    public function iCanGetAMessageWithLowSeverity(): void
    {
        $message = Message::low('Not important');

        static::assertSame(Message::SEVERITY_LOW, $message->getSeverity());
        static::assertSame('Not important', $message->getMessage());
    }

    /**
     * @test
     */
    public function iCanGetAMessageWithMediumSeverity(): void
    {
        $message = Message::medium('Quite important');

        static::assertSame(Message::SEVERITY_MEDIUM, $message->getSeverity());
        static::assertSame('Quite important', $message->getMessage());
    }

    /**
     * @test
     */
    public function iCanGetAMessageWithHighSeverity(): void
    {
        $message = Message::high('Very important');

        static::assertSame(Message::SEVERITY_HIGH, $message->getSeverity());
        static::assertSame('Very important', $message->getMessage());
    }

    /**
     * @test
     */
    public function iCanSerializeAMessageIntoJson(): void
    {
        $message = Message::high('Very important');

        static::assertSame(
            '{"message":"Very important","severity":"high"}',
            json_encode($message, JSON_THROW_ON_ERROR)
        );
    }

    /**
     * @test
     */
    public function aMessageBagCanHaveSeveralMessages(): void
    {
        $bag = new MessageBag();
        $bag->add(Message::high('Very important'));

        static::assertSame(1, $bag->count());
        static::assertSame(1, count($bag));
        static::assertSame(1, count($bag->all()));
        foreach ($bag as $message) {
            static::assertInstanceOf(Message::class, $message);
        }
    }

    /**
     * @test
     */
    public function iCanSerializeAMessageBagIntoJson(): void
    {
        $bag = new MessageBag();
        $bag->add(Message::high('Very important'));

        static::assertSame('[{"message":"Very important","severity":"high"}]', json_encode($bag, JSON_THROW_ON_ERROR));
    }
}
