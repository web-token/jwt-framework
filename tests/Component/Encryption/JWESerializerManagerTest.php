<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Encryption;

use InvalidArgumentException;
use Jose\Component\Core\Exception\InvalidSerializationException;
use Jose\Component\Core\Exception\UnrecognizedSerializationException;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Core\Util\BoundedJsonDecoder;
use Jose\Component\Encryption\JWE;
use Jose\Component\Encryption\Serializer\CompactSerializer;
use Jose\Component\Encryption\Serializer\JSONFlattenedSerializer;
use Jose\Component\Encryption\Serializer\JSONGeneralSerializer;
use Jose\Component\Encryption\Serializer\JWESerializer;
use Jose\Component\Encryption\Serializer\JWESerializerManager;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Throwable;
use function sprintf;
use function str_repeat;

/**
 * A serializer rejects an input of another serialization with an UnrecognizedSerializationException: the manager then
 * chains the exception of the serializer the input belongs to, whatever the order of the serializers.
 *
 * @internal
 */
final class JWESerializerManagerTest extends TestCase
{
    private const PARTS = '"iv":"AAAA","ciphertext":"AAAA","tag":"AAAA"';

    #[DataProvider('inputsOfAnotherSerialization')]
    #[Test]
    public function aSerializerRejectsAnInputOfAnotherSerializationAsUnrecognized(
        JWESerializer $serializer,
        string $input,
        string $message
    ): void {
        $this->expectException(UnrecognizedSerializationException::class);
        $this->expectExceptionMessage($message);

        $serializer->unserialize($input);
    }

    #[DataProvider('invalidTokensOfTheSerialization')]
    #[Test]
    public function aSerializerRejectsAnInvalidTokenOfItsSerializationWithoutTheMark(
        JWESerializer $serializer,
        string $token
    ): void {
        try {
            $serializer->unserialize($token);
            static::fail('The token should have been rejected.');
        } catch (InvalidArgumentException $exception) {
            static::assertNotInstanceOf(UnrecognizedSerializationException::class, $exception);
        }
    }

    /**
     * @param list<JWESerializer> $serializers
     */
    #[DataProvider('tokensForTheManager')]
    #[Test]
    public function theManagerChainsTheExceptionOfTheSerializerTheTokenBelongsTo(
        array $serializers,
        string $token,
        string $message,
        string $reason,
        bool $recognized
    ): void {
        try {
            (new JWESerializerManager($serializers))->unserialize($token);
            static::fail('The token should have been rejected.');
        } catch (InvalidSerializationException $exception) {
            static::assertSame('Unsupported input.', $exception->getMessage());
            static::assertSame(0, $exception->getCode());
            $previous = $exception->getPrevious();
            static::assertNotNull($previous);
            static::assertSame($message, $previous->getMessage());
            static::assertSame($reason, self::reason($previous));
            static::assertSame($recognized, ! $previous instanceof UnrecognizedSerializationException);
        }
    }

    /**
     * A serializer of another library may reject every input: the bound of a token of a serializer of this library
     * comes first, and a serializer that marks the inputs it does not recognize is skipped.
     */
    #[Test]
    public function theSerializersOfAnotherLibraryDoNotHideTheReason(): void
    {
        $compact = new CompactSerializer();
        $values = '[' . str_repeat('0,', BoundedJsonDecoder::MAX_VALUES) . '0]';
        $beyondTheBound = Base64UrlSafe::encodeUnpadded(
            '{"alg":"A128KW","enc":"A128GCM","x":' . $values . '}'
        ) . '.AAAA.AAAA.AAAA.AAAA';
        $unmarked = self::serializerOfAnotherLibrary(new InvalidArgumentException('Not a token of this library.'));
        $marked = self::serializerOfAnotherLibrary(
            new UnrecognizedSerializationException('Not a token of this library.')
        );

        static::assertSame(
            'The JSON documents of the token hold more JSON values than the 4096 that are decoded.',
            self::chainedReason([$compact, $unmarked], $beyondTheBound)
        );
        static::assertSame('Unsupported input.', self::chainedReason([$compact, $marked], self::badProtectedHeader()));
    }

    /**
     * @return iterable<string, array{JWESerializer, string, string}>
     */
    public static function inputsOfAnotherSerialization(): iterable
    {
        $compact = new CompactSerializer();
        $flattened = new JSONFlattenedSerializer();
        $general = new JSONGeneralSerializer();
        $compactToken = self::protectedHeader() . '.AAAA.AAAA.AAAA.AAAA';
        $flattenedToken = self::flattened(self::protectedHeader());
        $generalToken = self::general(self::protectedHeader());

        yield 'compact, not a token' => [$compact, 'This is not a token', 'Unsupported input'];
        yield 'compact, three parts' => [$compact, 'e30.AAAA.AAAA', 'Unsupported input'];
        yield 'compact, a flattened token' => [$compact, $flattenedToken, 'Unsupported input'];
        yield 'compact, JSON with four dots' => [
            $compact,
            sprintf(
                '{"protected":"%s","unprotected":{"jku":"https://a.example.com/x.json","kid":"y.z"},%s}',
                self::protectedHeader(),
                self::PARTS
            ),
            'Unsupported input',
        ];
        yield 'flattened, not a token' => [$flattened, 'This is not a token', 'Unsupported input.'];
        yield 'flattened, a compact token' => [$flattened, $compactToken, 'Unsupported input.'];
        yield 'flattened, a list' => [$flattened, '[1]', 'Unsupported input.'];
        yield 'flattened, a general token' => [$flattened, $generalToken, 'Unsupported input.'];
        yield 'general, not a token' => [$general, 'This is not a token', 'Unsupported input.'];
        yield 'general, a compact token' => [$general, $compactToken, 'Unsupported input.'];
        yield 'general, a string' => [$general, '"x"', 'Unsupported input.'];
        yield 'general, a flattened token' => [$general, $flattenedToken, 'Unsupported input.'];
    }

    /**
     * @return iterable<string, array{JWESerializer, string}>
     */
    public static function invalidTokensOfTheSerialization(): iterable
    {
        $invalidJson = Base64UrlSafe::encodeUnpadded('{');

        yield 'compact, a protected header that is not an object' => [
            new CompactSerializer(),
            self::badProtectedHeader(),
        ];
        yield 'compact, a protected header that is not JSON' => [
            new CompactSerializer(),
            $invalidJson . '.AAAA.AAAA.AAAA.AAAA',
        ];
        yield 'compact, a protected header of an impossible length' => [
            new CompactSerializer(),
            'e30AA.AAAA.AAAA.AAAA.AAAA',
        ];
        yield 'compact, an initialization vector of an impossible length' => [
            new CompactSerializer(),
            self::protectedHeader() . '.AAAA.A.AAAA.AAAA',
        ];
        yield 'flattened, a protected header that is not JSON' => [
            new JSONFlattenedSerializer(),
            self::flattened($invalidJson),
        ];
        yield 'general, a protected header that is not JSON' => [
            new JSONGeneralSerializer(),
            self::general($invalidJson),
        ];
    }

    /**
     * @return iterable<string, array{list<JWESerializer>, string, string, string, bool}>
     */
    public static function tokensForTheManager(): iterable
    {
        $orders = [
            'compact first' => [new CompactSerializer(), new JSONFlattenedSerializer(), new JSONGeneralSerializer()],
            'compact last' => [new JSONFlattenedSerializer(), new JSONGeneralSerializer(), new CompactSerializer()],
            'general first' => [new JSONGeneralSerializer(), new CompactSerializer(), new JSONFlattenedSerializer()],
        ];
        $invalidJson = Base64UrlSafe::encodeUnpadded('{');
        $tokens = [
            'a compact token whose protected header is not an object' => [
                self::badProtectedHeader(),
                'Unsupported input',
                'Unsupported input.',
            ],
            'a compact token whose protected header is not JSON' => [
                $invalidJson . '.AAAA.AAAA.AAAA.AAAA',
                'Unsupported input',
                'Syntax error',
            ],
            'a flattened token whose protected header is not JSON' => [
                self::flattened($invalidJson),
                'Unsupported input.',
                'Syntax error',
            ],
            'a general token whose protected header is not JSON' => [
                self::general($invalidJson),
                'Unsupported input.',
                'Syntax error',
            ],
        ];
        foreach ($orders as $order => $serializers) {
            foreach ($tokens as $name => [$token, $message, $reason]) {
                yield sprintf('%s, %s', $name, $order) => [$serializers, $token, $message, $reason, true];
            }
            yield sprintf('not a token, %s: the exception of the last serializer', $order) => [
                $serializers,
                'This is not a token',
                $order === 'compact last' ? 'Unsupported input' : 'Unsupported input.',
                $order === 'compact last' ? 'Unsupported input' : 'Syntax error',
                false,
            ];
        }
    }

    /**
     * @param list<JWESerializer> $serializers
     */
    private static function chainedReason(array $serializers, string $token): string
    {
        try {
            (new JWESerializerManager($serializers))->unserialize($token);
        } catch (InvalidSerializationException $exception) {
            $previous = $exception->getPrevious();
            static::assertNotNull($previous);

            return self::reason($previous);
        }
        static::fail('The token should have been rejected.');
    }

    /**
     * The message of the innermost exception of the chain.
     */
    private static function reason(Throwable $exception): string
    {
        while ($exception->getPrevious() !== null) {
            $exception = $exception->getPrevious();
        }

        return $exception->getMessage();
    }

    private static function serializerOfAnotherLibrary(Throwable $rejection): JWESerializer
    {
        return new class($rejection) implements JWESerializer {
            public function __construct(
                private readonly Throwable $rejection
            ) {
            }

            public function name(): string
            {
                return 'another_library';
            }

            public function displayName(): string
            {
                return 'Another library';
            }

            public function serialize(JWE $jws, ?int $recipientIndex = null): string
            {
                return '';
            }

            public function unserialize(string $input): JWE
            {
                throw $this->rejection;
            }
        };
    }

    private static function badProtectedHeader(): string
    {
        return Base64UrlSafe::encodeUnpadded('"x"') . '.AAAA.AAAA.AAAA.AAAA';
    }

    private static function flattened(string $protectedHeader): string
    {
        return sprintf('{"protected":"%s","encrypted_key":"AAAA",%s}', $protectedHeader, self::PARTS);
    }

    private static function general(string $protectedHeader): string
    {
        return sprintf(
            '{"protected":"%s","recipients":[{"encrypted_key":"AAAA"}],%s}',
            $protectedHeader,
            self::PARTS
        );
    }

    private static function protectedHeader(): string
    {
        return Base64UrlSafe::encodeUnpadded('{"alg":"A128KW","enc":"A128GCM"}');
    }
}
