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

use Jose\Component\Checker\InvalidClaimException;
use Jose\Component\Checker\IssuedAtChecker;
use PHPUnit\Framework\TestCase;

/**
 * @group ClaimChecker
 * @group functional
 *
 * @internal
 */
class IssuedAtClaimCheckerTest extends TestCase
{
    /**
     * @test
     */
    public function anIssuedAtClaimMustBeAnInteger(): void
    {
        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessage('"iat" must be an integer.');

        $checker = new IssuedAtChecker();
        $checker->checkClaim('foo');
    }

    /**
     * @test
     */
    public function theIssuedAtClaimIsInTheFutur(): void
    {
        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessage('The JWT is issued in the future.');

        $checker = new IssuedAtChecker();
        $checker->checkClaim(time() + 3600);
    }

    /**
     * @test
     */
    public function theIssuedAtClaimIsInThePast(): void
    {
        $checker = new IssuedAtChecker();
        $checker->checkClaim(time() - 3600);
        static::assertEquals('iat', $checker->supportedClaim());
    }
}
