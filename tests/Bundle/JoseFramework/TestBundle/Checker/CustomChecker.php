<?php

declare(strict_types=1);

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
        if ($value === true) {
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
        if ($value === true) {
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
