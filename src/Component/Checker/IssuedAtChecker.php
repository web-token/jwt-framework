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
 * This class is a claim checker.
 * When the "iat" is present, it will compare the value with the current timestamp.
 */
final class IssuedAtChecker implements ClaimChecker
{
    private const CLAIM_NAME = 'iat';

    private $allowedTimeDrift;

    public function __construct(int $allowedTimeDrift = 0)
    {
        $this->allowedTimeDrift = $allowedTimeDrift;
    }

    public function checkClaim($value): void
    {
        if (!\is_int($value)) {
            throw new InvalidClaimException('The claim "iat" must be an integer.', self::CLAIM_NAME, $value);
        }
        if (\time() < $value - $this->allowedTimeDrift) {
            throw new InvalidClaimException('The JWT is issued in the future.', self::CLAIM_NAME, $value);
        }
    }

    public function supportedClaim(): string
    {
        return self::CLAIM_NAME;
    }
}
