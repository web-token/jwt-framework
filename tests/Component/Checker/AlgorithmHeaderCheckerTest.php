<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Checker;

use Jose\Component\Checker\AlgorithmChecker;
use Jose\Component\Checker\InvalidHeaderException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
final class AlgorithmHeaderCheckerTest extends TestCase
{
    #[Test]
    public function anAlgorithmMustBeAString(): void
    {
        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessage('"alg" must be a string.');

        $checker = new AlgorithmChecker(['foo']);
        $checker->checkHeader(1);
    }

    #[Test]
    public function theAlgorithmHeaderIsNotAllowed(): void
    {
        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessage('Unsupported algorithm.');

        $checker = new AlgorithmChecker(['foo']);
        $checker->checkHeader('bar');
    }

    #[Test]
    public function theAlgorithmHeaderIsSupported(): void
    {
        $checker = new AlgorithmChecker(['foo']);
        $checker->checkHeader('foo');
        static::assertFalse($checker->protectedHeaderOnly());
        static::assertSame('alg', $checker->supportedHeader());
    }
}
