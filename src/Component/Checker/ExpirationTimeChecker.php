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

namespace Jose\Component\Checker;

use function is_float;
use function is_int;

/**
 * This class is a claim checker.
 * When the "exp" is present, it will compare the value with the current timestamp.
 */
final class ExpirationTimeChecker implements ClaimChecker, HeaderChecker
{
    private const NAME = 'exp';

    /**
     * @var int
     */
    private $allowedTimeDrift;
    /**
     * @var bool
     */
    private $protectedHeaderOnly;

    public function __construct(int $allowedTimeDrift = 0, bool $protectedHeaderOnly = false)
    {
        $this->allowedTimeDrift = $allowedTimeDrift;
        $this->protectedHeaderOnly = $protectedHeaderOnly;
    }

    /**
     * {@inheritdoc}
     *
     * @throws InvalidClaimException if the claim "exp" is not valid
     */
    public function checkClaim($value): void
    {
        if (!is_float($value) && !is_int($value)) {
            throw new InvalidClaimException('"exp" must be an integer.', self::NAME, $value);
        }
        if (time() > $value + $this->allowedTimeDrift) {
            throw new InvalidClaimException('The token expired.', self::NAME, $value);
        }
    }

    public function supportedClaim(): string
    {
        return self::NAME;
    }

    /**
     * @param mixed $value
     *
     * @throws InvalidHeaderException if the claim "exp" is not valid
     */
    public function checkHeader($value): void
    {
        if (!is_float($value) && !is_int($value)) {
            throw new InvalidHeaderException('"exp" must be an integer.', self::NAME, $value);
        }
        if (time() > $value + $this->allowedTimeDrift) {
            throw new InvalidHeaderException('The token expired.', self::NAME, $value);
        }
    }

    public function supportedHeader(): string
    {
        return self::NAME;
    }

    public function protectedHeaderOnly(): bool
    {
        return $this->protectedHeaderOnly;
    }
}
