<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Checker\Tests;

use Jose\Component\Checker\AudienceChecker;
use PHPUnit\Framework\TestCase;

/**
 * @group ClaimCheckerManager
 * @group Functional
 */
final class AudienceTest extends TestCase
{
    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Bad audience.
     */
    public function testAudienceMustBeAStringOrAnArrayOfStrings()
    {
        $checker = new AudienceChecker('foo');
        $checker->checkHeader(1);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Bad audience.
     */
    public function testBadAudience()
    {
        $checker = new AudienceChecker('foo');
        $checker->checkHeader('bar');
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Bad audience.
     */
    public function testBadAudienceList()
    {
        $checker = new AudienceChecker('foo');
        $checker->checkHeader(['bar']);
    }

    public function testSuccess()
    {
        $checker = new AudienceChecker('foo');
        $checker->checkHeader('foo');
        $checker->checkHeader(['foo']);
        self::assertFalse($checker->protectedHeaderOnly());
        self::assertEquals('aud', $checker->supportedHeader());
    }
}
