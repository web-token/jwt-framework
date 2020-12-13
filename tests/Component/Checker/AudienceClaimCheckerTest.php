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

use Jose\Component\Checker\AudienceChecker;
use Jose\Component\Checker\InvalidClaimException;
use PHPUnit\Framework\TestCase;

/**
 * @group ClaimChecker
 * @group functional
 *
 * @internal
 */
class AudienceClaimCheckerTest extends TestCase
{
    /**
     * @test
     */
    public function anAudienceClaimMustBeAStringOrAnArrayOfStrings(): void
    {
        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessage('Bad audience.');

        $checker = new AudienceChecker('foo');
        $checker->checkClaim(1);
    }

    /**
     * @test
     */
    public function theAudienceClaimIsNotKnown(): void
    {
        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessage('Bad audience.');

        $checker = new AudienceChecker('foo');
        $checker->checkClaim('bar');
    }

    /**
     * @test
     */
    public function theAudienceClaimListDoesNotContainTheCurrentAudience(): void
    {
        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessage('Bad audience.');

        $checker = new AudienceChecker('foo');
        $checker->checkClaim(['bar']);
    }

    /**
     * @test
     */
    public function theAudienceClaimIsSupported(): void
    {
        $checker = new AudienceChecker('foo');
        $checker->checkClaim('foo');
        $checker->checkClaim(['foo']);
        static::assertEquals('aud', $checker->supportedClaim());
    }
}
