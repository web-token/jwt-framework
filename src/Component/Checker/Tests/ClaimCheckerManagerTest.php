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
use Jose\Component\Checker\ClaimCheckerManager;
use PHPUnit\Framework\TestCase;

/**
 * @group ClaimChecker
 * @group unit
 *
 * @internal
 * @coversNothing
 */
final class ClaimCheckerManagerTest extends TestCase
{
    /**
     * @test
     */
    public function getCheckers(): void
    {
        $checkers = [
            new AudienceChecker('some-expected-audience'),
        ];

        $expectedCheckers = [
            'aud' => $checkers[0],
        ];

        $sut = new ClaimCheckerManager($checkers);

        static::assertEquals(
            $expectedCheckers,
            $sut->getCheckers()
        );
    }
}
