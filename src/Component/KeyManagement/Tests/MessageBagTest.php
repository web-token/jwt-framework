<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\KeyManagement\Tests;

use Jose\Component\KeyManagement\KeyAnalyzer\Message;
use Jose\Component\KeyManagement\KeyAnalyzer\MessageBag;
use PHPUnit\Framework\TestCase;

/**
 * @group Unit
 * @group JWKAnalyzer
 */
class MessageBagTest extends TestCase
{
    /**
     * @test
     */
    public function iCanGetAMessageWithLowSeverity()
    {
        $message = Message::low('Not important');

        self::assertEquals(Message::SEVERITY_LOW, $message->getSeverity());
        self::assertEquals('Not important', $message->getMessage());
    }

    /**
     * @test
     */
    public function iCanGetAMessageWithMediumSeverity()
    {
        $message = Message::medium('Quite important');

        self::assertEquals(Message::SEVERITY_MEDIUM, $message->getSeverity());
        self::assertEquals('Quite important', $message->getMessage());
    }

    /**
     * @test
     */
    public function iCanGetAMessageWithHighSeverity()
    {
        $message = Message::high('Very important');

        self::assertEquals(Message::SEVERITY_HIGH, $message->getSeverity());
        self::assertEquals('Very important', $message->getMessage());
    }

    /**
     * @test
     */
    public function iCanSerializeAMessageIntoJson()
    {
        $message = Message::high('Very important');

        self::assertEquals('{"message":"Very important","severity":"high"}', json_encode($message));
    }

    /**
     * @test
     */
    public function aMessageBagCanHaveSeveralMessages()
    {
        $bag = new MessageBag();
        $bag->add(Message::high('Very important'));

        self::assertEquals(1, $bag->count());
        self::assertEquals(1, count($bag));
        self::assertEquals(1, count($bag->all()));
        foreach ($bag as $message) {
            self::assertInstanceOf(Message::class, $message);
        }
    }

    /**
     * @test
     */
    public function iCanSerializeAMessageBagIntoJson()
    {
        $bag = new MessageBag();
        $bag->add(Message::high('Very important'));

        self::assertEquals('[{"message":"Very important","severity":"high"}]', json_encode($bag));
    }
}
