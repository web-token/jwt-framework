<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Checker;

use Jose\Component\Checker\InvalidClaimException;
use Jose\Component\Checker\IssuedAtChecker;
use Jose\Tests\Component\Checker\Stub\MockClock;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
final class IssuedAtClaimCheckerTest extends TestCase
{
    /**
     * @test
     */
    public function anIssuedAtClaimMustBeAnInteger(): void
    {
        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessage('"iat" must be an integer.');

        $clock = new MockClock();
        $checker = new IssuedAtChecker(clock: $clock);
        $checker->checkClaim('foo');
    }

    /**
     * @test
     */
    public function theIssuedAtClaimIsInTheFutur(): void
    {
        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessage('The JWT is issued in the future.');

        $clock = new MockClock();
        $checker = new IssuedAtChecker(clock: $clock);
        $checker->checkClaim($clock->now()->getTimestamp() + 3600);
    }

    /**
     * @test
     */
    public function theIssuedAtClaimIsInThePast(): void
    {
        $clock = new MockClock();
        $checker = new IssuedAtChecker(clock: $clock);
        $checker->checkClaim($clock->now()->getTimestamp() - 3600);
        static::assertSame('iat', $checker->supportedClaim());
    }
}
