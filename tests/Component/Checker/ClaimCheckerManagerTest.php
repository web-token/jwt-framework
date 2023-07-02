<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Checker;

use Jose\Component\Checker\AudienceChecker;
use Jose\Component\Checker\ClaimCheckerManager;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
final class ClaimCheckerManagerTest extends TestCase
{
    #[Test]
    public function getCheckers(): void
    {
        $checkers = [new AudienceChecker('some-expected-audience')];

        $expectedCheckers = [
            'aud' => $checkers[0],
        ];

        $sut = new ClaimCheckerManager($checkers);

        static::assertSame($expectedCheckers, $sut->getCheckers());
    }
}
