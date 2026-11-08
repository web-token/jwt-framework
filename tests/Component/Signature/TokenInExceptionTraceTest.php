<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Signature;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSLoader;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JSONFlattenedSerializer;
use Jose\Component\Signature\Serializer\JSONGeneralSerializer;
use Jose\Component\Signature\Serializer\JWSSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use Jose\Tests\Component\Core\ExceptionTraceArgumentsTrait;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The token given to the parsers and to the loader may be content the library decrypted, as the inner token of a
 * nested token. Refused, it must not be among the arguments recorded in the trace.
 *
 * @internal
 */
final class TokenInExceptionTraceTest extends TestCase
{
    use ExceptionTraceArgumentsTrait;

    private const CONTENT = 'known to the issuer and to the recipient only';

    #[Test]
    #[DataProvider('refusedInputs')]
    public function theRefusedInputIsNotAmongTheRecordedArguments(JWSSerializer $serializer, string $input): void
    {
        $exception = self::failureOf(static fn (): JWS => $serializer->unserialize($input));

        static::assertTrue(self::argumentsAreRecorded($exception), 'The arguments are not recorded.');
        static::assertSame([], self::callsHolding($exception, self::CONTENT));
    }

    #[Test]
    public function theRefusedTokenIsNotAmongTheArgumentsRecordedByTheLoader(): void
    {
        $loader = new JWSLoader(
            new JWSSerializerManager([
                new CompactSerializer(),
                new JSONFlattenedSerializer(),
                new JSONGeneralSerializer(),
            ]),
            new JWSVerifier(new AlgorithmManager([new HS256()])),
            null
        );
        $key = new JWK([
            'kty' => 'oct',
            'k' => 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
        ]);

        $exception = self::failureOf(
            static fn (): JWS => $loader->loadAndVerifyWithKey(self::CONTENT, $key, $signature)
        );

        static::assertTrue(self::argumentsAreRecorded($exception), 'The arguments are not recorded.');
        static::assertSame([], self::callsHolding($exception, self::CONTENT));
    }

    /**
     * @return iterable<string, array{JWSSerializer, string}>
     */
    public static function refusedInputs(): iterable
    {
        yield 'compact' => [new CompactSerializer(), self::CONTENT];
        yield 'JSON flattened' => [new JSONFlattenedSerializer(), self::CONTENT];
        yield 'JSON general' => [new JSONGeneralSerializer(), self::CONTENT];
        yield 'JSON general, payload that is not base64url' => [
            new JSONGeneralSerializer(),
            JsonConverter::encode([
                'payload' => self::CONTENT,
                'signatures' => [[
                    'signature' => '',
                ]],
            ]),
        ];
    }
}
