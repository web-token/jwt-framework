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

use Jose\Component\Checker\NotBeforeChecker;
use PHPUnit\Framework\TestCase;

/**
 * @group ClaimChecker
 * @group functional
 *
 * @internal
 */
class NotBeforeClaimCheckerTest extends TestCase
{
    /**
     * @test
     */
    public function theNotBeforeClaimMustBeAnInteger()
    {
        $this->expectException(\Jose\Component\Checker\InvalidClaimException::class);
        $this->expectExceptionMessage('"nbf" must be an integer.');

        $checker = new NotBeforeChecker();
        $checker->checkClaim('foo');
    }

    /**
     * @test
     */
    public function theNotBeforeClaimIsInTheFutur()
    {
        $this->expectException(\Jose\Component\Checker\InvalidClaimException::class);
        $this->expectExceptionMessage('The JWT can not be used yet.');

        $checker = new NotBeforeChecker();
        $checker->checkClaim(time() + 3600);
    }

    /**
     * @test
     */
    public function theNotBeforeClaimIsInThePast()
    {
        $checker = new NotBeforeChecker();
        $checker->checkClaim(time() - 3600);
        static::assertEquals('nbf', $checker->supportedClaim());
    }
}
