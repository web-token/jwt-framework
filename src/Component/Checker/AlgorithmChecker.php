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

namespace Jose\Component\Checker;

/**
 * This class is a header parameter checker.
 * When the "alg" header parameter is present, it will check if the value is within the allowed ones.
 */
final class AlgorithmChecker implements HeaderChecker
{
    private const HEADER_NAME = 'alg';

    /**
     * @var bool
     */
    private $protectedHeader = false;

    /**
     * @var string[]
     */
    private $supportedAlgorithms;

    /**
     * AlgorithmChecker constructor.
     *
     * @param string[] $supportedAlgorithms
     */
    public function __construct(array $supportedAlgorithms, bool $protectedHeader = false)
    {
        $this->supportedAlgorithms = $supportedAlgorithms;
        $this->protectedHeader = $protectedHeader;
    }

    /**
     * {@inheritdoc}
     */
    public function checkHeader($value)
    {
        if (!\is_string($value)) {
            throw new InvalidHeaderException('"alg" must be a string.', self::HEADER_NAME, $value);
        }
        if (!\in_array($value, $this->supportedAlgorithms, true)) {
            throw new InvalidHeaderException('Unsupported algorithm.', self::HEADER_NAME, $value);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function supportedHeader(): string
    {
        return self::HEADER_NAME;
    }

    /**
     * {@inheritdoc}
     */
    public function protectedHeaderOnly(): bool
    {
        return $this->protectedHeader;
    }
}
