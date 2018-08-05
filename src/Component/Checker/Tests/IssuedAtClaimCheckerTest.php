<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Checker\Tests;

use Jose\Component\Checker\IssuedAtChecker;
use PHPUnit\Framework\TestCase;

/**
 * @group ClaimChecker
 * @group Functional
 */
class IssuedAtClaimCheckerTest extends TestCase
{
    /**
     * @test
     * @expectedException \Jose\Component\Checker\InvalidClaimException
     * @expectedExceptionMessage "iat" must be an integer.
     */
    public function anIssuedAtClaimMustBeAnInteger()
    {
        $checker = new IssuedAtChecker();
        $checker->checkClaim('foo');
    }

    /**
     * @test
     * @expectedException \Jose\Component\Checker\InvalidClaimException
     * @expectedExceptionMessage The JWT is issued in the future.
     */
    public function theIssuedAtClaimIsInTheFutur()
    {
        $checker = new IssuedAtChecker();
        $checker->checkClaim(\time() + 3600);
    }

    /**
     * @test
     */
    public function theIssuedAtClaimIsInThePast()
    {
        $checker = new IssuedAtChecker();
        $checker->checkClaim(\time() - 3600);
        static::assertEquals('iat', $checker->supportedClaim());
    }
}
