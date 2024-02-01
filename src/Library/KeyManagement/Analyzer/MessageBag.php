<?php

declare(strict_types=1);

namespace Jose\Component\KeyManagement\Analyzer;

use ArrayIterator;
use Countable;
use IteratorAggregate;
use JsonSerializable;
use Traversable;
use function count;

class MessageBag implements JsonSerializable, IteratorAggregate, Countable
{
    /**
     * @var Message[]
     */
    private array $messages = [];

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

    public function jsonSerialize(): array
    {
        return array_values($this->messages);
    }

    public function count(): int
    {
        return count($this->messages);
    }

    public function getIterator(): Traversable
    {
        return new ArrayIterator($this->messages);
    }
}
