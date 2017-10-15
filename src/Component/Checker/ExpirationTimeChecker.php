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

final class ExpirationTimeChecker implements ClaimCheckerInterface
{
    private const CLAIM_NAME = 'exp';

    /**
     * {@inheritdoc}
     */
    public function checkClaim($value)
    {
        if (!is_int($value)) {
            throw new \InvalidArgumentException('"exp" must be an integer.');
        }
        if (time() > $value) {
            throw new \InvalidArgumentException('The JWT has expired.');
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
