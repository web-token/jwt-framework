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

/**
 * Class Message.
 */
final class Message implements \JsonSerializable
{
    /**
     * @var string
     */
    private $message;

    /**
     * @var string
     */
    private $severity;

    public const SEVERITY_LOW = 'low';

    public const SEVERITY_MEDIUM = 'medium';

    public const SEVERITY_HIGH = 'high';

    /**
     * Message constructor.
     *
     * @param string $message
     * @param string $severity
     */
    private function __construct(string $message, string $severity)
    {
        $this->message = $message;
        $this->severity = $severity;
    }

    /**
     * @param string $message
     *
     * @return Message
     */
    public static function low(string $message): self
    {
        return new self($message, self::SEVERITY_LOW);
    }

    /**
     * @param string $message
     *
     * @return Message
     */
    public static function medium(string $message): self
    {
        return new self($message, self::SEVERITY_MEDIUM);
    }

    /**
     * @param string $message
     *
     * @return Message
     */
    public static function high(string $message): self
    {
        return new self($message, self::SEVERITY_HIGH);
    }

    /**
     * @return string
     */
    public function getMessage(): string
    {
        return $this->message;
    }

    /**
     * @return string
     */
    public function getSeverity(): string
    {
        return $this->severity;
    }

    /**
     * {@inheritdoc}
     */
    public function jsonSerialize()
    {
        return [
            'message' => $this->message,
            'severity' => $this->severity,
        ];
    }
}
