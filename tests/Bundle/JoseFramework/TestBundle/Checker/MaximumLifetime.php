<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\TestBundle\Checker;

use Psr\Clock\ClockInterface;
use function is_int;

/**
 * A rule an application adds to the "exp" claim with a CallableChecker: the token expires within the next hour.
 */
final readonly class MaximumLifetime
{
    public function __construct(
        private ClockInterface $clock
    ) {
    }

    public function __invoke(mixed $exp): bool
    {
        return is_int($exp) && $exp <= $this->clock->now()
            ->getTimestamp() + 3600;
    }
}
