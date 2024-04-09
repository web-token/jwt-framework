<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\TestBundle\Checker;

use InvalidArgumentException;
use Jose\Component\Checker\ClaimChecker;
use Jose\Component\Checker\HeaderChecker;
use Override;

class CustomChecker implements ClaimChecker, HeaderChecker
{
    #[Override]
    public function checkClaim($value): void
    {
        if ($value === true) {
            throw new InvalidArgumentException('Custom checker!');
        }
    }

    #[Override]
    public function supportedClaim(): string
    {
        return 'custom';
    }

    #[Override]
    public function checkHeader($value): void
    {
        if ($value === true) {
            throw new InvalidArgumentException('Custom checker!');
        }
    }

    #[Override]
    public function supportedHeader(): string
    {
        return 'custom';
    }

    #[Override]
    public function protectedHeaderOnly(): bool
    {
        return true;
    }
}
