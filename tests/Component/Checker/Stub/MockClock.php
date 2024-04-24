<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Checker\Stub;

use DateTimeImmutable;
use Override;
use Psr\Clock\ClockInterface;

final readonly class MockClock implements ClockInterface
{
    public function __construct(
        private DateTimeImmutable $now = new DateTimeImmutable(),
    ) {
    }

    #[Override]
    public function now(): DateTimeImmutable
    {
        return $this->now;
    }
}
