<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Checker;

use Jose\Component\Checker\InvalidClaimException;
use Jose\Component\Checker\NotBeforeChecker;
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

        $checker = new NotBeforeChecker();
        $checker->checkClaim('foo');
    }

    /**
     * @test
     */
    public function theNotBeforeClaimIsInTheFutur(): void
    {
        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessage('The JWT can not be used yet.');

        $checker = new NotBeforeChecker();
        $checker->checkClaim(time() + 3600);
    }

    /**
     * @test
     */
    public function theNotBeforeClaimIsInThePast(): void
    {
        $checker = new NotBeforeChecker();
        $checker->checkClaim(time() - 3600);
        static::assertSame('nbf', $checker->supportedClaim());
    }
}
