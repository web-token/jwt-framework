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

namespace Jose\Component\Checker;

/**
 * Class AlgorithmChecker.
 */
final class AlgorithmChecker implements HeaderCheckerInterface
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
     * AudienceChecker constructor.
     *
     * @param string[] $supportedAlgorithms
     * @param bool     $protectedHeader
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
        if (!is_string($value)) {
            throw new \InvalidArgumentException('"alg" must be a string.');
        }
        if (!in_array($value, $this->supportedAlgorithms)) {
            throw new \InvalidArgumentException('Unsupported algorithm.');
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
