<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Checker;

use Jose\Component\Checker\InvalidClaimException;
use Jose\Component\Checker\NotBeforeChecker;
use Jose\Tests\Component\Checker\Stub\MockClock;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
final class NotBeforeClaimCheckerTest extends TestCase
{
    /**
     * @test
     */
    public function theNotBeforeClaimMustBeAnInteger(): void
    {
        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessage('"nbf" must be an integer.');

        $clock = new MockClock();
        $checker = new NotBeforeChecker(clock: $clock);
        $checker->checkClaim('foo');
    }

    /**
     * @test
     */
    public function theNotBeforeClaimIsInTheFutur(): void
    {
        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessage('The JWT can not be used yet.');

        $clock = new MockClock();
        $checker = new NotBeforeChecker(clock: $clock);
        $checker->checkClaim($clock->now()->getTimestamp() + 3600);
    }

    /**
     * @test
     */
    public function theNotBeforeClaimIsInThePast(): void
    {
        $clock = new MockClock();
        $checker = new NotBeforeChecker(clock: $clock);
        $checker->checkClaim($clock->now()->getTimestamp() - 3600);
        static::assertSame('nbf', $checker->supportedClaim());
    }
}
