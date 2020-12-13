<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Tests\Component\Checker;

use Jose\Component\Checker\AlgorithmChecker;
use Jose\Component\Checker\InvalidHeaderException;
use PHPUnit\Framework\TestCase;

/**
 * @group HeaderChecker
 * @group functional
 *
 * @internal
 */
class AlgorithmHeaderCheckerTest extends TestCase
{
    /**
     * @test
     */
    public function anAlgorithmMustBeAString(): void
    {
        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessage('"alg" must be a string.');

        $checker = new AlgorithmChecker(['foo']);
        $checker->checkHeader(1);
    }

    /**
     * @test
     */
    public function theAlgorithmHeaderIsNotAllowed(): void
    {
        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessage('Unsupported algorithm.');

        $checker = new AlgorithmChecker(['foo']);
        $checker->checkHeader('bar');
    }

    /**
     * @test
     */
    public function theAlgorithmHeaderIsSupported(): void
    {
        $checker = new AlgorithmChecker(['foo']);
        $checker->checkHeader('foo');
        static::assertFalse($checker->protectedHeaderOnly());
        static::assertEquals('alg', $checker->supportedHeader());
    }
}
