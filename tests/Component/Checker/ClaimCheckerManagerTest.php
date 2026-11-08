<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Checker;

use Jose\Component\Checker\AudienceChecker;
use Jose\Component\Checker\CallableChecker;
use Jose\Component\Checker\ClaimChecker;
use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Checker\ExpirationTimeChecker;
use Jose\Component\Checker\IssuedAtChecker;
use Jose\Tests\Component\Checker\Stub\MockClock;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function is_int;
use function sprintf;
use const E_USER_DEPRECATED;

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
    public function aSecondCheckerOfTheSameClaimIsDeprecated(ClaimChecker $first, ClaimChecker $second): void
    {
        $deprecations = $this->collectDeprecations(static function () use ($first, $second): void {
            new ClaimCheckerManager([$first, $second]);
        });

        static::assertSame([
            sprintf(
                'Since web-token/jwt-library 4.3.0: Building a claim checker manager with more than one checker of the claim "%s" is deprecated and will not be possible in 5.0.0: only the last one is kept, so "%s" replaces "%s", which never runs. Combine the rules of a claim in a single checker.',
                $first->supportedClaim(),
                $second::class,
                $first::class
            ),
        ], $deprecations);
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
    public function theLastCheckerOfAClaimIsStillTheOnlyOneThatRuns(): void
    {
        $replacement = new AudienceChecker('tenant-42');

        $deprecations = $this->collectDeprecations(static function () use ($replacement): void {
            $sut = new ClaimCheckerManager([new AudienceChecker('api'), $replacement]);

            static::assertSame([
                'aud' => $replacement,
            ], $sut->getCheckers());
            static::assertSame([
                'aud' => ['other', 'tenant-42'],
            ], $sut->check([
                'aud' => ['other', 'tenant-42'],
            ]));
        });

        static::assertCount(1, $deprecations);
    }

    #[Test]
    public function theSameCheckerListedTwiceIsNotDeprecated(): void
    {
        $checker = new AudienceChecker('api');

        $deprecations = $this->collectDeprecations(static function () use ($checker): void {
            $sut = new ClaimCheckerManager([$checker, new IssuedAtChecker(new MockClock()), $checker]);

            static::assertSame(['aud', 'iat'], array_keys($sut->getCheckers()));
        });

        static::assertSame([], $deprecations);
    }

    /**
     * @param callable(): void $callback
     *
     * @return list<string>
     */
    private function collectDeprecations(callable $callback): array
    {
        $deprecations = [];
        set_error_handler(static function (int $errno, string $errstr) use (&$deprecations): bool {
            $deprecations[] = $errstr;

            return true;
        }, E_USER_DEPRECATED);

        try {
            $callback();
        } finally {
            restore_error_handler();
        }

        return $deprecations;
    }
}
