<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Checker;

use Jose\Component\Checker\InvalidHeaderException;
use Jose\Component\Checker\UnencodedPayloadChecker;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
final class UnencodedPayloadHeaderCheckerTest extends TestCase
{
    #[Test]
    public function theB64HeaderMustBeAnBoolean(): void
    {
        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessage('"b64" must be a boolean.');

        $checker = new UnencodedPayloadChecker();
        $checker->checkHeader('foo');
    }

    #[Test]
    public function theB64HeaderIsABoolean(): void
    {
        $checker = new UnencodedPayloadChecker();
        $checker->checkHeader(true);
        $checker->checkHeader(false);
        static::assertTrue($checker->protectedHeaderOnly());
        static::assertSame('b64', $checker->supportedHeader());
    }
}
