<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2019 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\KeyManagement\Analyzer;

class MessageBag implements \JsonSerializable, \IteratorAggregate, \Countable
{
    /**
     * @var Message[]
     */
    private $messages = [];

    /**
     * Adds a message to the message bag.
     */
    public function add(Message $message): void
    {
        $this->messages[] = $message;
    }

    /**
     * Returns all messages.
     *
     * @return Message[]
     */
    public function all(): array
    {
        return $this->messages;
    }

    public function jsonSerialize()
    {
        return \array_values($this->messages);
    }

    public function count()
    {
        return \count($this->messages);
    }

    public function getIterator()
    {
        return new \ArrayIterator($this->messages);
    }
}
