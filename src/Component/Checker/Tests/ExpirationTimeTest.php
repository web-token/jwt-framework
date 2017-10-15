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

use Jose\Component\Checker\ExpirationTimeChecker;
use PHPUnit\Framework\TestCase;

/**
 * @group ClaimCheckerManager
 * @group Functional
 */
final class ExpirationTimeTest extends TestCase
{
    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage "exp" must be an integer.
     */
    public function testExpirationTimeMustBeAnInteger()
    {
        $checker = new ExpirationTimeChecker();
        $checker->checkClaim('foo');
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The JWT has expired.
     */
    public function testExpirationTime()
    {
        $checker = new ExpirationTimeChecker();
        $checker->checkClaim(time() - 1);
    }

    public function testSuccess()
    {
        $checker = new ExpirationTimeChecker();
        $checker->checkClaim(time() + 3600);
        self::assertEquals('exp', $checker->supportedClaim());
    }
}
