<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Checker\Stub;

use DateTimeImmutable;
use Psr\Clock\ClockInterface;

final class MockClock implements ClockInterface
{
    public function __construct(
        private readonly DateTimeImmutable $now = new DateTimeImmutable(),
    ) {
    }

    public function now(): DateTimeImmutable
    {
        return $this->now;
    }
}
