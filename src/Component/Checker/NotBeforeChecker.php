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
 * Class NotBeforeChecker.
 */
final class NotBeforeChecker implements ClaimCheckerInterface, HeaderCheckerInterface
{
    private const CLAIM_NAME = 'nbf';

    /**
     * @var bool
     */
    private $protectedHeader = false;

    /**
     * NotBeforeChecker constructor.
     *
     * @param bool $protectedHeader
     */
    public function __construct(bool $protectedHeader = false)
    {
        $this->protectedHeader = $protectedHeader;
    }

    /**
     * {@inheritdoc}
     */
    public function checkClaim($value)
    {
        return $this->checkValue($value);
    }

    /**
     * {@inheritdoc}
     */
    public function checkHeader($value)
    {
        return $this->checkValue($value);
    }

    /**
     * @param $value
     *
     * @throws \InvalidArgumentException
     */
    private function checkValue($value)
    {
        if (!is_int($value)) {
            throw new \InvalidArgumentException('The claim "nbf" must be an integer.');
        }
        if (time() < $value) {
            throw new \InvalidArgumentException('The JWT can not be used yet.');
        }
    }

    /**
     * {@inheritdoc}
     */
    public function supportedClaim(): string
    {
        return self::CLAIM_NAME;
    }

    /**
     * {@inheritdoc}
     */
    public function supportedHeader(): string
    {
        return self::CLAIM_NAME;
    }

    /**
     * {@inheritdoc}
     */
    public function protectedHeaderOnly(): bool
    {
        return $this->protectedHeader;
    }
}
