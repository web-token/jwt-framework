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

use Jose\Component\Checker\NotBeforeChecker;
use PHPUnit\Framework\TestCase;

/**
 * @group ClaimCheckerManager
 * @group Functional
 */
final class NotBeforeTest extends TestCase
{
    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage "nbf" must be an integer.
     */
    public function testNotBeforeMustBeAnInteger()
    {
        $checker = new NotBeforeChecker();
        $checker->checkHeader('foo');
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The JWT can not be used yet.
     */
    public function testCannotBeUsedNow()
    {
        $checker = new NotBeforeChecker();
        $checker->checkHeader(time()+3600);
    }

    public function testSuccess()
    {
        $checker = new NotBeforeChecker();
        $checker->checkHeader(time() - 3600);
        self::assertFalse($checker->protectedHeaderOnly());
        self::assertEquals('nbf', $checker->supportedHeader());
    }
}
