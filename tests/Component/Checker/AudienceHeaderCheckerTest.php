<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Checker;

use Jose\Component\Checker\AudienceChecker;
use Jose\Component\Checker\InvalidHeaderException;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
final class AudienceHeaderCheckerTest extends TestCase
{
    /**
     * @test
     */
    public function anAudienceHeaderMustBeAStringOrAnArrayOfStrings(): void
    {
        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessage('Bad audience.');

        $checker = new AudienceChecker('foo');
        $checker->checkHeader(1);
    }

    /**
     * @test
     */
    public function theAudienceHeaderIsNotKnown(): void
    {
        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessage('Bad audience.');

        $checker = new AudienceChecker('foo');
        $checker->checkHeader('bar');
    }

    /**
     * @test
     */
    public function theAudienceHeaderListDoesNotContainTheCurrentAudience(): void
    {
        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessage('Bad audience.');

        $checker = new AudienceChecker('foo');
        $checker->checkHeader(['bar']);
    }

    /**
     * @test
     */
    public function theAudienceHeaderIsSupported(): void
    {
        $checker = new AudienceChecker('foo');
        $checker->checkHeader('foo');
        $checker->checkHeader(['foo']);
        static::assertFalse($checker->protectedHeaderOnly());
        static::assertSame('aud', $checker->supportedHeader());
    }
}
