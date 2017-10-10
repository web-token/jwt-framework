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

namespace Jose\Bundle\Checker\Tests\TestBundle\Checker;

use Jose\Component\Checker\ClaimCheckerInterface;
use Jose\Component\Checker\HeaderCheckerInterface;

/**
 * Class CustomChecker.
 */
final class CustomChecker implements ClaimCheckerInterface, HeaderCheckerInterface
{
    public function checkClaim($value)
    {
        if (true === $value) {
            throw new \InvalidArgumentException('Custom checker!');
        }
    }

    public function supportedClaim(): string
    {
        return 'custom';
    }

    public function checkHeader($value)
    {
        if (true === $value) {
            throw new \InvalidArgumentException('Custom checker!');
        }
    }

    public function supportedHeader(): string
    {
        return 'custom';
    }

    public function protectedHeaderOnly(): bool
    {
        return true;
    }
}
