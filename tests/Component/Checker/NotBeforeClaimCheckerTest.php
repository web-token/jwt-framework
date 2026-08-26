<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Checker;

use Jose\Component\Checker\InvalidClaimException;
use Jose\Component\Checker\NotBeforeChecker;
use Jose\Tests\Component\Checker\Stub\MockClock;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
final class NotBeforeClaimCheckerTest extends TestCase
{
    #[Test]
    public function theNotBeforeClaimMustBeAnInteger(): void
    {
        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessage('"nbf" must be an integer.');

        $clock = new MockClock();
        $checker = new NotBeforeChecker(clock: $clock);
        $checker->checkClaim('foo');
    }

    #[Test]
    public function theNotBeforeClaimIsInTheFutur(): void
    {
        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessage('The JWT can not be used yet.');

        $clock = new MockClock();
        $checker = new NotBeforeChecker(clock: $clock);
        $checker->checkClaim($clock->now()->getTimestamp() + 3600);
    }

    #[Test]
    public function theNotBeforeClaimIsInThePast(): void
    {
        $clock = new MockClock();
        $checker = new NotBeforeChecker(clock: $clock);
        $checker->checkClaim($clock->now()->getTimestamp() - 3600);
        static::assertSame('nbf', $checker->supportedClaim());
    }
}
