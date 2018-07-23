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

interface ClaimChecker
{
    /**
     * When the token has the applicable claim, the value is checked.
     * If for some reason the value is not valid, an InvalidClaimException must be thrown.
     *
     *
     * @throws InvalidClaimException
     */
    public function checkClaim($value);

    /**
     * The method returns the claim to be checked.
     */
    public function supportedClaim(): string;
}
