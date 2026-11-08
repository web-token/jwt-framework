<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Checker;

use Jose\Component\Checker\AudienceChecker;
use Jose\Component\Checker\HeaderChecker;
use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Checker\TypeChecker;
use Jose\Component\Core\Exception\InvalidArgumentException;
use Jose\Tests\Component\Checker\Stub\TokenSupport;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;

/**
 * @internal
 */
final class HeaderCheckerManagerTest extends TestCase
{
    #[DataProvider('twoCheckersOfTheSameHeaderParameter')]
    #[Test]
    public function aSecondCheckerOfTheSameHeaderParameterIsRejected(HeaderChecker $first, HeaderChecker $second): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(sprintf(
            'The header parameter "%s" is given two checkers, "%s" and "%s", but a header checker manager takes a single checker per header parameter. Combine the rules of a header parameter in a single checker.',
            $first->supportedHeader(),
            $first::class,
            $second::class
        ));

        new HeaderCheckerManager([$first, $second], [new TokenSupport()]);
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
    public function theSameCheckerListedTwiceIsAccepted(): void
    {
        $checker = new TypeChecker(['at+jwt']);

        $sut = new HeaderCheckerManager([$checker, new AudienceChecker('api'), $checker], [new TokenSupport()]);

        static::assertSame(['typ', 'aud'], array_keys($sut->getCheckers()));
    }
}
