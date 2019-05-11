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

use Jose\Component\Checker\AudienceChecker;
use PHPUnit\Framework\TestCase;

/**
 * @group HeaderChecker
 * @group functional
 *
 * @internal
 * @coversNothing
 */
class AudienceHeaderCheckerTest extends TestCase
{
    /**
     * @test
     */
    public function anAudienceHeaderMustBeAStringOrAnArrayOfStrings()
    {
        $this->expectException(\Jose\Component\Checker\InvalidHeaderException::class);
        $this->expectExceptionMessage('Bad audience.');

        $checker = new AudienceChecker('foo');
        $checker->checkHeader(1);
    }

    /**
     * @test
     */
    public function theAudienceHeaderIsNotKnown()
    {
        $this->expectException(\Jose\Component\Checker\InvalidHeaderException::class);
        $this->expectExceptionMessage('Bad audience.');

        $checker = new AudienceChecker('foo');
        $checker->checkHeader('bar');
    }

    /**
     * @test
     */
    public function theAudienceHeaderListDoesNotContainTheCurrentAudience()
    {
        $this->expectException(\Jose\Component\Checker\InvalidHeaderException::class);
        $this->expectExceptionMessage('Bad audience.');

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
