<?php

declare(strict_types=1);

namespace Jose\Component\KeyManagement\Analyzer;

use JsonSerializable;

class Message implements JsonSerializable
{
    final public const SEVERITY_LOW = 'low';

    final public const SEVERITY_MEDIUM = 'medium';

    final public const SEVERITY_HIGH = 'high';

    private function __construct(
        private readonly string $message,
        private readonly string $severity
    ) {
    }

    /**
     * Creates a message with severity=low.
     */
    public static function low(string $message): self
    {
        return new self($message, self::SEVERITY_LOW);
    }

    /**
     * Creates a message with severity=medium.
     */
    public static function medium(string $message): self
    {
        return new self($message, self::SEVERITY_MEDIUM);
    }

    /**
     * Creates a message with severity=high.
     */
    public static function high(string $message): self
    {
        return new self($message, self::SEVERITY_HIGH);
    }

    /**
     * Returns the message.
     */
    public function getMessage(): string
    {
        return $this->message;
    }

    /**
     * Returns the severity of the message.
     */
    public function getSeverity(): string
    {
        return $this->severity;
    }

    public function jsonSerialize(): array
    {
        return [
            'message' => $this->message,
            'severity' => $this->severity,
        ];
    }
}
