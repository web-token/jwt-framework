<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Easy;

use Jose\Component\Checker\ClaimChecker;
use Jose\Component\Checker\HeaderChecker;
use Jose\Component\Checker\InvalidClaimException;
use Jose\Component\Checker\InvalidHeaderException;

final class CallableChecker implements ClaimChecker, HeaderChecker
{
    /**
     * @var string
     */
    private $key;

    /**
     * @var callable
     */
    private $callable;

    public function __construct(string $key, callable $callable)
    {
        $this->key = $key;
        $this->callable = $callable;
    }

    /**
     * @param mixed $value
     *
     * @throws InvalidClaimException if the claim is invalid
     */
    public function checkClaim($value): void
    {
        $callable = $this->callable;
        $isValid = $callable($value);
        if (!$isValid) {
            throw new InvalidClaimException(sprintf('Invalid claim "%s"', $this->key), $this->key, $value);
        }
    }

    public function supportedClaim(): string
    {
        return $this->key;
    }

    /**
     * {@inheritdoc}
     */
    public function checkHeader($value): void
    {
        $callable = $this->callable;
        $isValid = $callable($value);
        if (!$isValid) {
            throw new InvalidHeaderException(sprintf('Invalid header "%s"', $this->key), $this->key, $value);
        }
    }

    public function supportedHeader(): string
    {
        return $this->key;
    }

    public function protectedHeaderOnly(): bool
    {
        return true;
    }
}
