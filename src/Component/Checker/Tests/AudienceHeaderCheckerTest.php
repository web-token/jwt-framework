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
 * @group HeaderChecker
 * @group Functional
 */
class AudienceHeaderCheckerTest extends TestCase
{
    /**
     * @test
     * @expectedException \Jose\Component\Checker\InvalidHeaderException
     * @expectedExceptionMessage Bad audience.
     */
    public function anAudienceHeaderMustBeAStringOrAnArrayOfStrings()
    {
        $checker = new AudienceChecker('foo');
        $checker->checkHeader(1);
    }

    /**
     * @test
     * @expectedException \Jose\Component\Checker\InvalidHeaderException
     * @expectedExceptionMessage Bad audience.
     */
    public function theAudienceHeaderIsNotKnown()
    {
        $checker = new AudienceChecker('foo');
        $checker->checkHeader('bar');
    }

    /**
     * @test
     * @expectedException \Jose\Component\Checker\InvalidHeaderException
     * @expectedExceptionMessage Bad audience.
     */
    public function theAudienceHeaderListDoesNotContainTheCurrentAudience()
    {
        $checker = new AudienceChecker('foo');
        $checker->checkHeader(['bar']);
    }

    /**
     * @test
     */
    public function theAudienceHeaderIsSupported()
    {
        $checker = new AudienceChecker('foo');
        $checker->checkHeader('foo');
        $checker->checkHeader(['foo']);
        static::assertFalse($checker->protectedHeaderOnly());
        static::assertEquals('aud', $checker->supportedHeader());
    }
}
