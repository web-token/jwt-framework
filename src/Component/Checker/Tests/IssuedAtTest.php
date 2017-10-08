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

use Jose\Component\Checker\IssuedAtChecker;
use PHPUnit\Framework\TestCase;

/**
 * @group ClaimCheckerManager
 * @group Functional
 */
final class IssuedAtTest extends TestCase
{
    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage "iat" must be an integer.
     */
    public function testIssuedAtMustBeAnInteger()
    {
        $checker = new IssuedAtChecker();
        $checker->checkHeader('foo');
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The JWT is issued in the future.
     */
    public function testIssuedInTheFutur()
    {
        $checker = new IssuedAtChecker();
        $checker->checkHeader(time()+3600);
    }

    public function testSuccess()
    {
        $checker = new IssuedAtChecker();
        $checker->checkHeader(time() - 3600);
        self::assertFalse($checker->protectedHeaderOnly());
        self::assertEquals('iat', $checker->supportedHeader());
    }
}
