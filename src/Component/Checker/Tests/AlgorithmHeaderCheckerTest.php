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

use Jose\Component\Checker\AlgorithmChecker;
use PHPUnit\Framework\TestCase;

/**
 * @group HeaderChecker
 * @group Functional
 */
class AlgorithmHeaderCheckerTest extends TestCase
{
    /**
     * @test
     * @expectedException \Jose\Component\Checker\InvalidHeaderException
     * @expectedExceptionMessage "alg" must be a string.
     */
    public function anAlgorithmMustBeAString()
    {
        $checker = new AlgorithmChecker(['foo']);
        $checker->checkHeader(1);
    }

    /**
     * @test
     * @expectedException \Jose\Component\Checker\InvalidHeaderException
     * @expectedExceptionMessage Unsupported algorithm.
     */
    public function theAlgorithmHeaderIsNotAllowed()
    {
        $checker = new AlgorithmChecker(['foo']);
        $checker->checkHeader('bar');
    }

    /**
     * @test
     */
    public function theAlgorithmHeaderIsSupported()
    {
        $checker = new AlgorithmChecker(['foo']);
        $checker->checkHeader('foo');
        static::assertFalse($checker->protectedHeaderOnly());
        static::assertEquals('alg', $checker->supportedHeader());
    }
}
