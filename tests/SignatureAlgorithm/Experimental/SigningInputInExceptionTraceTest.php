<?php

declare(strict_types=1);

namespace Jose\Tests\SignatureAlgorithm\Experimental;

use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\MacAlgorithm;
use Jose\Experimental\Signature\Blake2b;
use Jose\Experimental\Signature\HS256_64;
use Jose\Tests\Component\Core\ExceptionTraceArgumentsTrait;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
final class SigningInputInExceptionTraceTest extends TestCase
{
    use ExceptionTraceArgumentsTrait;

    private const INPUT = 'eyJhbGciOiJub25lIn0.eyJjb25maWRlbnRpYWwiOiJjbGFpbXMifQ';

    private const SIGNATURE = 'signature of the token';

    #[Test]
    #[DataProvider('algorithms')]
    public function theSigningInputIsNotAmongTheRecordedArgumentsWhenTheKeyHasAnotherType(MacAlgorithm $algorithm): void
    {
        $key = new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
        ]);

        $exception = self::failureOf(static fn (): bool => $algorithm->verify($key, self::INPUT, self::SIGNATURE));

        static::assertNotSame([], self::callsHolding($exception, self::SIGNATURE), 'The arguments are not recorded.');
        static::assertSame([], self::callsHolding($exception, self::INPUT));
    }

    /**
     * @return iterable<string, array{MacAlgorithm}>
     */
    public static function algorithms(): iterable
    {
        yield 'HS256/64' => [new HS256_64()];
        yield 'BLAKE2B' => [new Blake2b()];
    }
}
