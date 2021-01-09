<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Tests\Component\KeyManagement;

use function count;
use Jose\Component\KeyManagement\Analyzer\Message;
use Jose\Component\KeyManagement\Analyzer\MessageBag;
use PHPUnit\Framework\TestCase;

/**
 * @group unit
 * @group JWKAnalyzer
 *
 * @internal
 */
class MessageBagTest extends TestCase
{
    /**
     * @test
     */
    public function iCanGetAMessageWithLowSeverity(): void
    {
        $message = Message::low('Not important');

        static::assertEquals(Message::SEVERITY_LOW, $message->getSeverity());
        static::assertEquals('Not important', $message->getMessage());
    }

    /**
     * @test
     */
    public function iCanGetAMessageWithMediumSeverity(): void
    {
        $message = Message::medium('Quite important');

        static::assertEquals(Message::SEVERITY_MEDIUM, $message->getSeverity());
        static::assertEquals('Quite important', $message->getMessage());
    }

    /**
     * @test
     */
    public function iCanGetAMessageWithHighSeverity(): void
    {
        $message = Message::high('Very important');

        static::assertEquals(Message::SEVERITY_HIGH, $message->getSeverity());
        static::assertEquals('Very important', $message->getMessage());
    }

    /**
     * @test
     */
    public function iCanSerializeAMessageIntoJson(): void
    {
        $message = Message::high('Very important');

        static::assertEquals('{"message":"Very important","severity":"high"}', json_encode($message));
    }

    /**
     * @test
     */
    public function aMessageBagCanHaveSeveralMessages(): void
    {
        $bag = new MessageBag();
        $bag->add(Message::high('Very important'));

        static::assertEquals(1, $bag->count());
        static::assertEquals(1, count($bag));
        static::assertEquals(1, count($bag->all()));
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

        static::assertEquals('[{"message":"Very important","severity":"high"}]', json_encode($bag));
    }
}
