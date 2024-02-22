<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Checker;

use Jose\Component\Checker\InvalidClaimException;
use Jose\Component\Checker\IssuedAtChecker;
use Jose\Tests\Component\Checker\Stub\MockClock;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
final class IssuedAtClaimCheckerTest extends TestCase
{
    #[Test]
    public function anIssuedAtClaimMustBeAnInteger(): void
    {
        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessage('"iat" must be an integer.');

        $clock = new MockClock();
        $checker = new IssuedAtChecker(clock: $clock);
        $checker->checkClaim('foo');
    }

    #[Test]
    public function theIssuedAtClaimIsInTheFutur(): void
    {
        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessage('The JWT is issued in the future.');

        $clock = new MockClock();
        $checker = new IssuedAtChecker(clock: $clock);
        $checker->checkClaim($clock->now()->getTimestamp() + 3600);
    }

    #[Test]
    public function theIssuedAtClaimIsInThePast(): void
    {
        $clock = new MockClock();
        $checker = new IssuedAtChecker(clock: $clock);
        $checker->checkClaim($clock->now()->getTimestamp() - 3600);
        static::assertSame('iat', $checker->supportedClaim());
    }
}
