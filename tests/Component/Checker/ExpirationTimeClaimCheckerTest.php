<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Checker;

use Jose\Component\Checker\ExpirationTimeChecker;
use Jose\Component\Checker\InvalidClaimException;
use Jose\Tests\Component\Checker\Stub\MockClock;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
final class ExpirationTimeClaimCheckerTest extends TestCase
{
    #[Test]
    public function theExpirationTimeClaimMustBeAnInteger(): void
    {
        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessage('"exp" must be an integer.');

        $clock = new MockClock();
        $checker = new ExpirationTimeChecker(clock: $clock);
        $checker->checkClaim('foo');
    }

    #[Test]
    public function theExpirationTimeIsInThePast(): void
    {
        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessage('The token expired.');

        $clock = new MockClock();
        $checker = new ExpirationTimeChecker(clock: $clock);
        $checker->checkClaim($clock->now()->getTimestamp() - 1);
    }

    #[Test]
    public function theExpirationTimeIsInTheFutur(): void
    {
        $clock = new MockClock();
        $checker = new ExpirationTimeChecker(clock: $clock);
        $checker->checkClaim($clock->now()->getTimestamp() + 3600);
        static::assertSame('exp', $checker->supportedClaim());
    }
}
