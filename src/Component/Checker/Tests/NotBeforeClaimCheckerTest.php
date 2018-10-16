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

use Jose\Component\Checker\NotBeforeChecker;
use PHPUnit\Framework\TestCase;

/**
 * @group ClaimChecker
 * @group Functional
 */
class NotBeforeClaimCheckerTest extends TestCase
{
    /**
     * @test
     * @expectedException \Jose\Component\Checker\InvalidClaimException
     * @expectedExceptionMessage "nbf" must be an integer.
     */
    public function theNotBeforeClaimMustBeAnInteger()
    {
        $checker = new NotBeforeChecker();
        $checker->checkClaim('foo');
    }

    /**
     * @test
     * @expectedException \Jose\Component\Checker\InvalidClaimException
     * @expectedExceptionMessage The JWT can not be used yet.
     */
    public function theNotBeforeClaimIsInTheFutur()
    {
        $checker = new NotBeforeChecker();
        $checker->checkClaim(\time() + 3600);
    }

    /**
     * @test
     */
    public function theNotBeforeClaimIsInThePast()
    {
        $checker = new NotBeforeChecker();
        $checker->checkClaim(\time() - 3600);
        static::assertEquals('nbf', $checker->supportedClaim());
    }
}
