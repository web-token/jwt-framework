<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Checker;

use Jose\Component\Checker\InvalidClaimException;
use Jose\Component\Checker\InvalidHeaderException;
use Jose\Component\Checker\IsEqualChecker;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
final class IsEqualCheckerTest extends TestCase
{
    /**
     * @test
     */
    public function theClaimIsInvalid(): void
    {
        $this->expectException(InvalidClaimException::class);

        $checker = new IsEqualChecker('foo', 'bar');
        $checker->checkClaim('baz');
    }

    /**
     * @test
     */
    public function theHeaderIsInvalid(): void
    {
        $this->expectException(InvalidHeaderException::class);

        $checker = new IsEqualChecker('foo', 'bar');
        $checker->checkHeader('baz');
    }

    /**
     * @test
     */
    public function theClaimIsSupported(): void
    {
        $checker = new IsEqualChecker('foo', 'bar');
        $checker->checkClaim('bar');
        static::assertSame('foo', $checker->supportedClaim());
    }

    /**
     * @test
     */
    public function theHeaderIsSupported(): void
    {
        $checker = new IsEqualChecker('foo', 'bar');
        $checker->checkHeader('bar');
        static::assertSame('foo', $checker->supportedHeader());
    }
}
