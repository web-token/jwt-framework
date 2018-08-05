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

use Jose\Component\Checker\AudienceChecker;
use PHPUnit\Framework\TestCase;

/**
 * @group ClaimChecker
 * @group Functional
 */
class AudienceClaimCheckerTest extends TestCase
{
    /**
     * @test
     * @expectedException \Jose\Component\Checker\InvalidClaimException
     * @expectedExceptionMessage Bad audience.
     */
    public function anAudienceClaimMustBeAStringOrAnArrayOfStrings()
    {
        $checker = new AudienceChecker('foo');
        $checker->checkClaim(1);
    }

    /**
     * @test
     * @expectedException \Jose\Component\Checker\InvalidClaimException
     * @expectedExceptionMessage Bad audience.
     */
    public function theAudienceClaimIsNotKnown()
    {
        $checker = new AudienceChecker('foo');
        $checker->checkClaim('bar');
    }

    /**
     * @test
     * @expectedException \Jose\Component\Checker\InvalidClaimException
     * @expectedExceptionMessage Bad audience.
     */
    public function theAudienceClaimListDoesNotContainTheCurrentAudience()
    {
        $checker = new AudienceChecker('foo');
        $checker->checkClaim(['bar']);
    }

    /**
     * @test
     */
    public function theAudienceClaimIsSupported()
    {
        $checker = new AudienceChecker('foo');
        $checker->checkClaim('foo');
        $checker->checkClaim(['foo']);
        static::assertEquals('aud', $checker->supportedClaim());
    }
}
