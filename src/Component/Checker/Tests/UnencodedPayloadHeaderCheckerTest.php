<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2019 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Checker\Tests;

use Jose\Component\Checker\UnencodedPayloadChecker;
use PHPUnit\Framework\TestCase;

/**
 * @group HeaderChecker
 * @group functional
 *
 * @internal
 * @coversNothing
 */
class UnencodedPayloadHeaderCheckerTest extends TestCase
{
    /**
     * @test
     */
    public function theB64HeaderMustBeAnBoolean()
    {
        $this->expectException(\Jose\Component\Checker\InvalidHeaderException::class);
        $this->expectExceptionMessage('"b64" must be a boolean.');

        $checker = new UnencodedPayloadChecker();
        $checker->checkHeader('foo');
    }

    /**
     * @test
     */
    public function theB64HeaderIsABoolean()
    {
        $checker = new UnencodedPayloadChecker();
        $checker->checkHeader(true);
        $checker->checkHeader(false);
        static::assertTrue($checker->protectedHeaderOnly());
        static::assertEquals('b64', $checker->supportedHeader());
    }
}
