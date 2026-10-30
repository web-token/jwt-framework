<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Checker;

use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Checker\InvalidHeaderException;
use Jose\Component\Checker\MissingMandatoryHeaderParameterException;
use Jose\Component\Checker\TypeChecker;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\Exception\InvalidArgumentException;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWSTokenSupport;
use Jose\Component\Signature\Serializer\JSONFlattenedSerializer;
use Jose\Tests\Component\Checker\Stub\Token;
use Jose\Tests\Component\Checker\Stub\TokenSupport;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\DoesNotPerformAssertions;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
final class TypeHeaderCheckerTest extends TestCase
{
    #[Test]
    public function theCheckerHandlesTheProtectedTypHeaderOnly(): void
    {
        $checker = new TypeChecker(['at+jwt']);

        static::assertSame('typ', $checker->supportedHeader());
        static::assertTrue($checker->protectedHeaderOnly());
    }

    #[Test]
    public function aSingleTypeCanBeGivenAsAString(): void
    {
        $checker = new TypeChecker('at+jwt');
        $checker->checkHeader('at+jwt');

        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessage('Unsupported type.');
        $checker->checkHeader('JWT');
    }

    #[Test]
    #[DataProvider('acceptedTypes')]
    #[DoesNotPerformAssertions]
    public function theTypeIsComparedCaseInsensitivelyWithAnOptionalApplicationPrefix(string $value): void
    {
        $checker = new TypeChecker(['at+jwt']);
        $checker->checkHeader($value);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function acceptedTypes(): iterable
    {
        yield 'as configured' => ['at+jwt'];
        yield 'upper case' => ['AT+JWT'];
        yield 'mixed case' => ['At+Jwt'];
        yield 'with the application/ prefix' => ['application/at+jwt'];
        yield 'with the application/ prefix in upper case' => ['APPLICATION/AT+JWT'];
    }

    #[Test]
    public function theAcceptedTypesAreNormalizedToo(): void
    {
        $checker = new TypeChecker(['Application/AT+JWT']);
        $checker->checkHeader('at+jwt');

        $this->expectException(InvalidHeaderException::class);
        $checker->checkHeader('dpop+jwt');
    }

    #[Test]
    #[DataProvider('rejectedTypes')]
    public function anotherTypeIsRejected(string $value): void
    {
        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessage('Unsupported type.');

        $checker = new TypeChecker(['at+jwt']);
        $checker->checkHeader($value);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function rejectedTypes(): iterable
    {
        yield 'generic JWT' => ['JWT'];
        yield 'another profile' => ['dpop+jwt'];
        yield 'another top-level type' => ['text/at+jwt'];
        yield 'prefix only' => ['application/'];
        yield 'empty string' => [''];
    }

    #[Test]
    public function theTypeMustBeAString(): void
    {
        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessage('"typ" must be a string.');

        $checker = new TypeChecker(['at+jwt']);
        $checker->checkHeader(['at+jwt']);
    }

    #[Test]
    public function theExceptionCarriesTheHeaderNameAndTheValue(): void
    {
        $checker = new TypeChecker(['at+jwt']);

        try {
            $checker->checkHeader('dpop+jwt');
            static::fail('An exception was expected.');
        } catch (InvalidHeaderException $exception) {
            static::assertSame('typ', $exception->getHeader());
            static::assertSame('dpop+jwt', $exception->getValue());
        }
    }

    #[Test]
    public function severalTypesCanBeAccepted(): void
    {
        $checker = new TypeChecker(['at+jwt', 'application/dpop+jwt']);
        $checker->checkHeader('AT+JWT');
        $checker->checkHeader('dpop+jwt');

        $this->expectException(InvalidHeaderException::class);
        $checker->checkHeader('JWT');
    }

    #[Test]
    public function atLeastOneTypeIsRequired(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('At least one accepted type must be provided.');

        new TypeChecker([]);
    }

    #[Test]
    #[DataProvider('invalidAcceptedTypes')]
    public function theAcceptedTypesMustBeNonEmptyStrings(mixed $type): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The accepted types must be non-empty strings.');

        new TypeChecker([$type]);
    }

    /**
     * @return iterable<string, array{mixed}>
     */
    public static function invalidAcceptedTypes(): iterable
    {
        yield 'empty string' => [''];
        yield 'integer' => [1];
        yield 'null' => [null];
    }

    #[Test]
    #[DoesNotPerformAssertions]
    public function aProtectedTypeIsCheckedByTheManager(): void
    {
        $manager = new HeaderCheckerManager([new TypeChecker(['at+jwt'])], [new TokenSupport()]);
        $token = new Token(null, [
            'alg' => 'HS256',
            'typ' => 'application/at+jwt',
        ], []);

        $manager->check($token, 0, ['typ']);
    }

    #[Test]
    public function aMissingTypeIsRejectedWhenListedAsMandatory(): void
    {
        $this->expectException(MissingMandatoryHeaderParameterException::class);
        $this->expectExceptionMessage('The following header parameters are mandatory: typ.');

        $manager = new HeaderCheckerManager([new TypeChecker(['at+jwt'])], [new TokenSupport()]);
        $token = new Token(null, [
            'alg' => 'HS256',
        ], []);

        $manager->check($token, 0, ['typ']);
    }

    #[Test]
    #[DoesNotPerformAssertions]
    public function aMissingTypeIsIgnoredWhenNotListedAsMandatory(): void
    {
        $manager = new HeaderCheckerManager([new TypeChecker(['at+jwt'])], [new TokenSupport()]);
        $token = new Token(null, [
            'alg' => 'HS256',
        ], []);

        $manager->check($token, 0);
    }

    #[Test]
    public function aWrongProtectedTypeIsRejectedByTheManager(): void
    {
        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessage('Unsupported type.');

        $manager = new HeaderCheckerManager([new TypeChecker(['at+jwt'])], [new TokenSupport()]);
        $token = new Token(null, [
            'alg' => 'HS256',
            'typ' => 'logout+jwt',
        ], []);

        $manager->check($token, 0, ['typ']);
    }

    #[Test]
    public function anUnprotectedTypeOfAJsonSerializedJwsDoesNotSatisfyTheCheck(): void
    {
        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessage('The header parameter "typ" must be protected.');

        $key = new JWK([
            'kty' => 'oct',
            'k' => 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
        ]);
        $algorithmManager = new AlgorithmManager([new HS256()]);
        $jws = (new JWSBuilder($algorithmManager))
            ->withPayload('{}')
            ->addSignature($key, [
                'alg' => 'HS256',
            ], [
                'typ' => 'at+jwt',
            ])
            ->build();
        $serializer = new JSONFlattenedSerializer();
        $jws = $serializer->unserialize($serializer->serialize($jws, 0));

        $manager = new HeaderCheckerManager([new TypeChecker(['at+jwt'])], [new JWSTokenSupport()]);
        $manager->check($jws, 0, ['typ']);
    }
}
