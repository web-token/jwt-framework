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

namespace Jose\Tests\Bundle\JoseFramework\TestBundle\Checker;

use InvalidArgumentException;
use Jose\Component\Checker\ClaimChecker;
use Jose\Component\Checker\HeaderChecker;

class CustomChecker implements ClaimChecker, HeaderChecker
{
    /**
     * {@inheritdoc}
     */
    public function checkClaim($value): void
    {
        if (true === $value) {
            throw new InvalidArgumentException('Custom checker!');
        }
    }

    public function supportedClaim(): string
    {
        return 'custom';
    }

    /**
     * {@inheritdoc}
     */
    public function checkHeader($value): void
    {
        if (true === $value) {
            throw new InvalidArgumentException('Custom checker!');
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
