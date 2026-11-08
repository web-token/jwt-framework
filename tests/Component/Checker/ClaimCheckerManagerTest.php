<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Checker;

use Jose\Component\Checker\AudienceChecker;
use Jose\Component\Checker\CallableChecker;
use Jose\Component\Checker\ClaimChecker;
use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Checker\ExpirationTimeChecker;
use Jose\Component\Checker\IssuedAtChecker;
use Jose\Component\Core\Exception\InvalidArgumentException;
use Jose\Tests\Component\Checker\Stub\MockClock;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function is_int;
use function sprintf;

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

    #[DataProvider('twoCheckersOfTheSameClaim')]
    #[Test]
    public function aSecondCheckerOfTheSameClaimIsRejected(ClaimChecker $first, ClaimChecker $second): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(sprintf(
            'The claim "%s" is given two checkers, "%s" and "%s", but a claim checker manager takes a single checker per claim. Combine the rules of a claim in a single checker.',
            $first->supportedClaim(),
            $first::class,
            $second::class
        ));

        new ClaimCheckerManager([$first, $second]);
    }

    /**
     * @return iterable<string, array{ClaimChecker, ClaimChecker}>
     */
    public static function twoCheckersOfTheSameClaim(): iterable
    {
        yield 'two audiences' => [new AudienceChecker('api'), new AudienceChecker('tenant-42')];
        yield 'the expiration time and a maximum lifetime' => [
            new ExpirationTimeChecker(new MockClock()),
            new CallableChecker('exp', static fn (mixed $exp): bool => is_int($exp) && $exp <= time() + 3600),
        ];
    }

    #[Test]
    public function theSameCheckerListedTwiceIsAccepted(): void
    {
        $checker = new AudienceChecker('api');

        $sut = new ClaimCheckerManager([$checker, new IssuedAtChecker(new MockClock()), $checker]);

        static::assertSame(['aud', 'iat'], array_keys($sut->getCheckers()));
    }
}
