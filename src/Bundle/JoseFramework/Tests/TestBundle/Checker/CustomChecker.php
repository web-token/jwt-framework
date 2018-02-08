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

namespace Jose\Bundle\JoseFramework\Tests\TestBundle\Checker;

use Jose\Component\Checker\ClaimChecker;
use Jose\Component\Checker\HeaderChecker;

class CustomChecker implements ClaimChecker, HeaderChecker
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
