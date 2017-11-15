<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\KeyManagement\KeyAnalyzer;

/**
 * Class MessageBag.
 */
final class MessageBag implements \JsonSerializable, \ArrayAccess, \IteratorAggregate, \Countable
{
    /**
     * @var Message[]
     */
    private $messages = [];

    /**
     * @param Message $message
     *
     * @return MessageBag
     */
    public function add(Message $message): MessageBag
    {
        $this->messages[] = $message;

        return $this;
    }

    /**
     * @return Message[]
     */
    public function all(): array
    {
        return $this->messages;
    }

    /**
     * {@inheritdoc}
     */
    public function jsonSerialize()
    {
        return array_values($this->messages);
    }

    /**
     * {@inheritdoc}
     */
    public function offsetExists($offset)
    {
        return isset($this->messages[$offset]);
    }

    /**
     * {@inheritdoc}
     */
    public function offsetGet($offset)
    {
        return isset($this->messages[$offset]) ? $this->messages[$offset] : null;
    }

    /**
     * {@inheritdoc}
     */
    public function offsetSet($offset, $value)
    {
        $this->messages[$offset] = $value;
    }

    /**
     * {@inheritdoc}
     */
    public function offsetUnset($offset)
    {
        unset($this->messages[$offset]);
    }

    /**
     * {@inheritdoc}
     */
    public function count()
    {
        return count($this->messages);
    }

    /**
     * {@inheritdoc}
     */
    public function getIterator()
    {
        return new \ArrayIterator($this->messages);
    }
}
