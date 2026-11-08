<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Checker;

use Jose\Component\Checker\AudienceChecker;
use Jose\Component\Checker\HeaderChecker;
use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Checker\TypeChecker;
use Jose\Tests\Component\Checker\Stub\Token;
use Jose\Tests\Component\Checker\Stub\TokenSupport;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;
use const E_USER_DEPRECATED;

/**
 * @internal
 */
final class HeaderCheckerManagerTest extends TestCase
{
    #[DataProvider('twoCheckersOfTheSameHeaderParameter')]
    #[Test]
    public function aSecondCheckerOfTheSameHeaderParameterIsDeprecated(HeaderChecker $first, HeaderChecker $second): void
    {
        $deprecations = $this->collectDeprecations(static function () use ($first, $second): void {
            new HeaderCheckerManager([$first, $second], [new TokenSupport()]);
        });

        static::assertSame([
            sprintf(
                'Since web-token/jwt-library 4.3.0: Building a header checker manager with more than one checker of the header parameter "%s" is deprecated and will not be possible in 5.0.0: only the last one is kept, so "%s" replaces "%s", which never runs. Combine the rules of a header parameter in a single checker.',
                $first->supportedHeader(),
                $second::class,
                $first::class
            ),
        ], $deprecations);
    }

    /**
     * @return iterable<string, array{HeaderChecker, HeaderChecker}>
     */
    public static function twoCheckersOfTheSameHeaderParameter(): iterable
    {
        yield 'two accepted types' => [new TypeChecker(['at+jwt']), new TypeChecker(['dpop+jwt'])];
        yield 'a protected audience, then an unprotected one' => [
            new AudienceChecker('api', true),
            new AudienceChecker('api'),
        ];
    }

    #[Test]
    public function theLastCheckerOfAHeaderParameterIsStillTheOnlyOneThatRuns(): void
    {
        $deprecations = $this->collectDeprecations(static function (): void {
            $sut = new HeaderCheckerManager(
                [new AudienceChecker('api', true), new AudienceChecker('api')],
                [new TokenSupport()]
            );

            $sut->check(new Token('{}', [], [
                'aud' => 'api',
            ]), 0);
        });

        static::assertCount(1, $deprecations);
    }

    #[Test]
    public function theSameCheckerListedTwiceIsNotDeprecated(): void
    {
        $checker = new TypeChecker(['at+jwt']);

        $deprecations = $this->collectDeprecations(static function () use ($checker): void {
            $sut = new HeaderCheckerManager([$checker, new AudienceChecker('api'), $checker], [new TokenSupport()]);

            static::assertSame(['typ', 'aud'], array_keys($sut->getCheckers()));
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
