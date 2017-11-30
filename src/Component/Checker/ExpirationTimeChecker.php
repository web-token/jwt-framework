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

final class ExpirationTimeChecker implements ClaimChecker
{
    private const CLAIM_NAME = 'exp';

    /**
     * @var int
     */
    private $allowedTimeDrift;

    /**
     * ExpirationTimeChecker constructor.
     *
     * @param int $allowedTimeDrift
     */
    public function __construct(int $allowedTimeDrift = 0)
    {
        $this->allowedTimeDrift = $allowedTimeDrift;
    }

    /**
     * {@inheritdoc}
     */
    public function checkClaim($value)
    {
        if (!is_int($value)) {
            throw new InvalidClaimException('"exp" must be an integer.', self::CLAIM_NAME, $value);
        }
        if (time() > $value + $this->allowedTimeDrift) {
            throw new InvalidClaimException('The JWT has expired.', self::CLAIM_NAME, $value);
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
