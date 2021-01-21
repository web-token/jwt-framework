<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Tests\Component\Checker;

use Jose\Component\Checker\ExpirationTimeChecker;
use Jose\Component\Checker\InvalidClaimException;
use PHPUnit\Framework\TestCase;

/**
 * @group ClaimChecker
 * @group functional
 *
 * @internal
 */
class ExpirationTimeClaimCheckerTest extends TestCase
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
        static::assertEquals('exp', $checker->supportedClaim());
    }
}
