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

use Jose\Component\Checker\UnencodedPayloadChecker;
use PHPUnit\Framework\TestCase;

/**
 * @group ClaimCheckerManager
 * @group Functional
 */
final class UnencodedPayloadTest extends TestCase
{
    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage "b64" must be a boolean.
     */
    public function testB64MustBeAnInteger()
    {
        $checker = new UnencodedPayloadChecker();
        $checker->checkHeader('foo');
    }


    public function testSuccess()
    {
        $checker = new UnencodedPayloadChecker();
        $checker->checkHeader(true);
        $checker->checkHeader(false);
        self::assertTrue($checker->protectedHeaderOnly());
        self::assertEquals('b64', $checker->supportedHeader());
    }
}
