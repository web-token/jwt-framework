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
final class NotBeforeChecker implements ClaimChecker
{
    private const CLAIM_NAME = 'nbf';

    /**
     * {@inheritdoc}
     */
    public function checkClaim($value)
    {
        if (!is_int($value)) {
            throw new InvalidClaimException('"nbf" must be an integer.', self::CLAIM_NAME, $value);
        }
        if (time() < $value) {
            throw new InvalidClaimException('The JWT can not be used yet.', self::CLAIM_NAME, $value);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function supportedClaim(): string
    {
        return self::CLAIM_NAME;
    }
}
