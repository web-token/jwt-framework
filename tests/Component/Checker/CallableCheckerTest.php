<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Checker;

use InvalidArgumentException;
use Jose\Component\Checker\CallableChecker;
use Jose\Component\Checker\InvalidClaimException;
use Jose\Component\Checker\InvalidHeaderException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use stdClass;

/**
 * @internal
 */
final class CallableCheckerTest extends TestCase
{
    #[Test]
    public function theCallableIsCallable(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The $callable argument must be a callable.');

        new CallableChecker('foo', 'not_a_callable');
    }

    #[Test]
    #[DataProvider('resultsOtherThanTrue')]
    public function theClaimIsInvalidWhenTheCallableDoesNotReturnTrue(mixed $result): void
    {
        $this->expectException(InvalidClaimException::class);

        $checker = new CallableChecker('foo', fn (mixed $value) => $result);
        $checker->checkClaim('baz');
    }

    #[Test]
    #[DataProvider('resultsOtherThanTrue')]
    public function theHeaderIsInvalidWhenTheCallableDoesNotReturnTrue(mixed $result): void
    {
        $this->expectException(InvalidHeaderException::class);

        $checker = new CallableChecker('foo', fn (mixed $value) => $result);
        $checker->checkHeader('baz');
    }

    #[Test]
    public function theClaimIsInvalid(): void
    {
        $this->expectException(InvalidClaimException::class);

        $checker = new CallableChecker('foo', fn (mixed $value) => $value === 'bar');
        $checker->checkClaim('baz');
    }

    #[Test]
    public function theHeaderIsInvalid(): void
    {
        $this->expectException(InvalidHeaderException::class);

        $checker = new CallableChecker('foo', fn (mixed $value) => $value === 'bar');
        $checker->checkHeader('baz');
    }

    #[Test]
    public function theClaimIsSupported(): void
    {
        $checker = new CallableChecker('foo', fn (mixed $value) => $value === 'bar');
        $checker->checkClaim('bar');

        static::assertSame('foo', $checker->supportedClaim());
    }

    #[Test]
    public function theHeaderIsSupported(): void
    {
        $checker = new CallableChecker('foo', fn (mixed $value) => $value === 'bar');
        $checker->checkHeader('bar');

        static::assertSame('foo', $checker->supportedHeader());
    }

    /**
     * @return iterable<string, array{mixed}>
     */
    public static function resultsOtherThanTrue(): iterable
    {
        yield 'false' => [false];
        yield 'null' => [null];
        yield 'zero' => [0];
        yield 'one' => [1];
        yield 'minus one' => [-1];
        yield 'string' => ['The value is not allowed.'];
        yield 'array' => [['The value is not allowed.']];
        yield 'object' => [new stdClass()];
    }
}
