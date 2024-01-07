<?php

declare(strict_types=1);

namespace Jose\Tests\Component\KeyManagement;

use Jose\Component\KeyManagement\Analyzer\Message;
use Jose\Component\KeyManagement\Analyzer\MessageBag;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use const JSON_THROW_ON_ERROR;

/**
 * @internal
 */
final class MessageBagTest extends TestCase
{
    #[Test]
    public function iCanGetAMessageWithLowSeverity(): void
    {
        $message = Message::low('Not important');

        static::assertSame(Message::SEVERITY_LOW, $message->getSeverity());
        static::assertSame('Not important', $message->getMessage());
    }

    #[Test]
    public function iCanGetAMessageWithMediumSeverity(): void
    {
        $message = Message::medium('Quite important');

        static::assertSame(Message::SEVERITY_MEDIUM, $message->getSeverity());
        static::assertSame('Quite important', $message->getMessage());
    }

    #[Test]
    public function iCanGetAMessageWithHighSeverity(): void
    {
        $message = Message::high('Very important');

        static::assertSame(Message::SEVERITY_HIGH, $message->getSeverity());
        static::assertSame('Very important', $message->getMessage());
    }

    #[Test]
    public function iCanSerializeAMessageIntoJson(): void
    {
        $message = Message::high('Very important');

        static::assertSame(
            '{"message":"Very important","severity":"high"}',
            json_encode($message, JSON_THROW_ON_ERROR)
        );
    }

    #[Test]
    public function aMessageBagCanHaveSeveralMessages(): void
    {
        $bag = new MessageBag();
        $bag->add(Message::high('Very important'));

        static::assertSame(1, $bag->count());
        static::assertCount(1, $bag);
        static::assertCount(1, $bag->all());
        static::assertContainsOnlyInstancesOf(Message::class, $bag);
    }

    #[Test]
    public function iCanSerializeAMessageBagIntoJson(): void
    {
        $bag = new MessageBag();
        $bag->add(Message::high('Very important'));

        static::assertSame('[{"message":"Very important","severity":"high"}]', json_encode($bag, JSON_THROW_ON_ERROR));
    }
}
