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
 * @group ClaimChecker
 * @group functional
 *
 * @internal
 * @coversNothing
 */
class AudienceClaimCheckerTest extends TestCase
{
    /**
     * @test
     */
    public function anAudienceClaimMustBeAStringOrAnArrayOfStrings()
    {
        $this->expectException(\Jose\Component\Checker\InvalidClaimException::class);
        $this->expectExceptionMessage('Bad audience.');

        $checker = new AudienceChecker('foo');
        $checker->checkClaim(1);
    }

    /**
     * @test
     */
    public function theAudienceClaimIsNotKnown()
    {
        $this->expectException(\Jose\Component\Checker\InvalidClaimException::class);
        $this->expectExceptionMessage('Bad audience.');

        $checker = new AudienceChecker('foo');
        $checker->checkClaim('bar');
    }

    /**
     * @test
     */
    public function theAudienceClaimListDoesNotContainTheCurrentAudience()
    {
        $this->expectException(\Jose\Component\Checker\InvalidClaimException::class);
        $this->expectExceptionMessage('Bad audience.');

        $checker = new AudienceChecker('foo');
        $checker->checkClaim(['bar']);
    }

    /**
     * @test
     */
    public function theAudienceClaimIsSupported()
    {
        $checker = new AudienceChecker('foo');
        $checker->checkClaim('foo');
        $checker->checkClaim(['foo']);
        static::assertEquals('aud', $checker->supportedClaim());
    }
}
