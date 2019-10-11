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

namespace Jose\Easy;

use Jose\Component\Checker\HeaderChecker;
use Jose\Component\Checker\InvalidHeaderException;

/**
 * This class is a header parameter checker.
 * When the "enc" header parameter is present, it will check if the value is within the allowed ones.
 */
final class ContentEncryptionAlgorithmChecker implements HeaderChecker
{
    private const HEADER_NAME = 'enc';

    /**
     * @var bool
     */
    private $protectedHeader = false;

    /**
     * @var string[]
     */
    private $supportedAlgorithms;

    /**
     * @param string[] $supportedAlgorithms
     */
    public function __construct(array $supportedAlgorithms, bool $protectedHeader = false)
    {
        $this->supportedAlgorithms = $supportedAlgorithms;
        $this->protectedHeader = $protectedHeader;
    }

    /**
     * {@inheritdoc}
     *
     * @throws InvalidHeaderException if the header is invalid
     */
    public function checkHeader($value): void
    {
        if (!\is_string($value)) {
            throw new InvalidHeaderException('"enc" must be a string.', self::HEADER_NAME, $value);
        }
        if (!\in_array($value, $this->supportedAlgorithms, true)) {
            throw new InvalidHeaderException('Unsupported algorithm.', self::HEADER_NAME, $value);
        }
    }

    public function supportedHeader(): string
    {
        return self::HEADER_NAME;
    }

    public function protectedHeaderOnly(): bool
    {
        return $this->protectedHeader;
    }
}
