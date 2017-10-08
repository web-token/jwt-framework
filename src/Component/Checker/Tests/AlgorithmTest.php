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

use Jose\Component\Checker\AlgorithmChecker;
use PHPUnit\Framework\TestCase;

/**
 * @group ClaimCheckerManager
 * @group Functional
 */
final class AlgorithmTest extends TestCase
{
    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage "alg" must be a string.
     */
    public function testAlgorithmMustBeAString()
    {
        $checker = new AlgorithmChecker(['foo']);
        $checker->checkHeader(1);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Unsupported algorithm.
     */
    public function testUnsupportedAlgorithm()
    {
        $checker = new AlgorithmChecker(['foo']);
        $checker->checkHeader('bar');
    }

    public function testSuccess()
    {
        $checker = new AlgorithmChecker(['foo']);
        $checker->checkHeader('foo');
        self::assertFalse($checker->protectedHeaderOnly());
        self::assertEquals('alg', $checker->supportedHeader());
    }
}
