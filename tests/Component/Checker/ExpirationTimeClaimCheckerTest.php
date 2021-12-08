<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Checker;

use Jose\Component\Checker\ExpirationTimeChecker;
use Jose\Component\Checker\InvalidClaimException;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
final class ExpirationTimeClaimCheckerTest extends TestCase
{
    /**
     * @test
     */
    public function theExpirationTimeClaimMustBeAnInteger(): void
    {
        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessage('"exp" must be an integer.');

        $checker = new ExpirationTimeChecker();
        $checker->checkClaim('foo');
    }

    /**
     * @test
     */
    public function theExpirationTimeIsInThePast(): void
    {
        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessage('The token expired.');

        $checker = new ExpirationTimeChecker();
        $checker->checkClaim(time() - 1);
    }

    /**
     * @test
     */
    public function theExpirationTimeIsInTheFutur(): void
    {
        $checker = new ExpirationTimeChecker();
        $checker->checkClaim(time() + 3600);
        static::assertSame('exp', $checker->supportedClaim());
    }
}
