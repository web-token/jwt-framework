<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Checker;

use InvalidArgumentException;
use Jose\Component\Checker\CallableChecker;
use Jose\Component\Checker\InvalidClaimException;
use Jose\Component\Checker\InvalidHeaderException;
use Jose\Component\Checker\IsEqualChecker;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
final class CallableCheckerTest extends TestCase
{
    /**
     * @test
     */
    public function theCallableIsCallable(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The $callable argument must be a callable.');

        new CallableChecker('foo', 'not_a_callable');
    }

    /**
     * @test
     */
    public function theCallableDoesNotReturnABoolean(): void
    {
        $this->expectException(InvalidClaimException::class);

        $checker = new CallableChecker('foo', fn (mixed $value) => 1);
        $checker->checkClaim('baz');

        $this->expectException(InvalidHeaderException::class);

        $checker = new CallableChecker('foo', fn (mixed $value) => 0);
        $checker->checkHeader('baz');
    }

    /**
     * @test
     */
    public function theClaimIsInvalid(): void
    {
        $this->expectException(InvalidClaimException::class);

        $checker = new CallableChecker('foo', fn (mixed $value) => $value === 'bar');
        $checker->checkClaim('baz');
    }

    /**
     * @test
     */
    public function theHeaderIsInvalid(): void
    {
        $this->expectException(InvalidHeaderException::class);

        $checker = new CallableChecker('foo', fn (mixed $value) => $value === 'bar');
        $checker->checkHeader('baz');
    }

    /**
     * @test
     */
    public function theClaimIsSupported(): void
    {
        $checker = new CallableChecker('foo', fn (mixed $value) => $value === 'bar');
        $checker->checkClaim('bar');

        static::assertSame('foo', $checker->supportedClaim());
    }

    /**
     * @test
     */
    public function theHeaderIsSupported(): void
    {
        $checker = new CallableChecker('foo', fn (mixed $value) => $value === 'bar');
        $checker->checkHeader('bar');

        static::assertSame('foo', $checker->supportedHeader());
    }
}
