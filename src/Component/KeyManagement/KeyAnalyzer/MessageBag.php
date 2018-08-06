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

namespace Jose\Component\KeyManagement\KeyAnalyzer;

class MessageBag implements \JsonSerializable, \IteratorAggregate, \Countable
{
    /**
     * @var Message[]
     */
    private $messages = [];

    /**
     * Adds a message to the message bag.
     *
     * @return MessageBag
     */
    public function add(Message $message): self
    {
        $this->messages[] = $message;

        return $this;
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
