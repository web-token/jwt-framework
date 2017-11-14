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
 * Class AudienceChecker.
 */
final class AudienceChecker implements ClaimChecker, HeaderChecker
{
    private const CLAIM_NAME = 'aud';

    /**
     * @var bool
     */
    private $protectedHeader = false;

    /**
     * @var string
     */
    private $audience;

    /**
     * AudienceChecker constructor.
     *
     * @param string $audience
     * @param bool   $protectedHeader
     */
    public function __construct(string $audience, bool $protectedHeader = false)
    {
        $this->audience = $audience;
        $this->protectedHeader = $protectedHeader;
    }

    /**
     * {@inheritdoc}
     */
    public function checkClaim($value)
    {
        return $this->checkValue($value, InvalidClaimException::class);
    }

    /**
     * {@inheritdoc}
     */
    public function checkHeader($value)
    {
        return $this->checkValue($value, InvalidHeaderException::class);
    }

    /**
     * @param mixed  $value
     * @param string $class
     *
     * @throws \InvalidArgumentException
     */
    private function checkValue($value, string $class)
    {
        if (is_string($value) && $value !== $this->audience) {
            throw new $class('Bad audience.', self::CLAIM_NAME, $value);
        } elseif (is_array($value) && !in_array($this->audience, $value)) {
            throw new $class('Bad audience.', self::CLAIM_NAME, $value);
        } elseif (!is_array($value) && !is_string($value)) {
            throw new $class('Bad audience.', self::CLAIM_NAME, $value);
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
