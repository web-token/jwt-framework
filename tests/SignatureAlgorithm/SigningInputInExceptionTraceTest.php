<?php

declare(strict_types=1);

namespace Jose\Tests\SignatureAlgorithm;

use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\EdDSA;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\Algorithm\MacAlgorithm;
use Jose\Component\Signature\Algorithm\PS256;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\Algorithm\SignatureAlgorithm;
use Jose\Tests\Component\Core\ExceptionTraceArgumentsTrait;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The signing input of the inner token of a nested token is content the library decrypted. A verification that throws,
 * for instance with a key of another type, must not leave it among the arguments recorded in the trace.
 *
 * @internal
 */
final class SigningInputInExceptionTraceTest extends TestCase
{
    use ExceptionTraceArgumentsTrait;

    private const INPUT = 'eyJhbGciOiJub25lIn0.eyJjb25maWRlbnRpYWwiOiJjbGFpbXMifQ';

    private const SIGNATURE = 'signature of the token';

    #[Test]
    #[DataProvider('keysOfAnotherType')]
    public function theSigningInputIsNotAmongTheRecordedArguments(
        MacAlgorithm|SignatureAlgorithm $algorithm,
        JWK $key
    ): void {
        $exception = self::failureOf(static fn (): bool => $algorithm->verify($key, self::INPUT, self::SIGNATURE));

        static::assertNotSame([], self::callsHolding($exception, self::SIGNATURE), 'The arguments are not recorded.');
        static::assertSame([], self::callsHolding($exception, self::INPUT));
    }

    /**
     * @return iterable<string, array{MacAlgorithm|SignatureAlgorithm, JWK}>
     */
    public static function keysOfAnotherType(): iterable
    {
        $octetKey = new JWK([
            'kty' => 'oct',
            'k' => 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
        ]);
        $ellipticCurveKey = new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
        ]);

        yield 'HS256' => [new HS256(), $ellipticCurveKey];
        yield 'ES256' => [new ES256(), $octetKey];
        yield 'EdDSA' => [new EdDSA(), $octetKey];
        yield 'RS256' => [new RS256(), $octetKey];
        yield 'PS256' => [new PS256(), $octetKey];
    }
}
