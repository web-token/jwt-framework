<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Signature;

use InvalidArgumentException;
use Jose\Component\Core\Exception\InvalidSerializationException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Core\Util\BoundedJsonDecoder;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JSONFlattenedSerializer;
use Jose\Component\Signature\Serializer\JSONGeneralSerializer;
use Jose\Component\Signature\Serializer\JWSSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use function array_fill_keys;
use function memory_get_peak_usage;
use function memory_get_usage;
use function memory_reset_peak_usage;
use function random_bytes;
use function range;
use function sprintf;
use function str_repeat;
use const JSON_ERROR_DEPTH;

/**
 * @internal
 */
final class JsonValueBoundTest extends SignatureTestCase
{
    private const TOO_MANY_VALUES = 'The JSON documents of the token hold more JSON values than the 4096 that are decoded.';

    private const TOO_DEEP = 'A JSON document of the token is nested too deeply.';

    /**
     * The member names are multiples of 131072: they all fall into the first bucket of a PHP array.
     */
    #[DataProvider('dataSerializers')]
    #[Test]
    public function aSignedTokenWhoseProtectedHeaderHoldsTooManyMembersIsRejected(JWSSerializer $serializer): void
    {
        $key = self::createKey();
        $members = array_fill_keys(range(0, (BoundedJsonDecoder::MAX_VALUES - 1) * 131072, 131072), 0);
        $jws = $this->getJWSBuilderFactory()
            ->create(['HS256'])
            ->create()
            ->withPayload('{}')
            ->addSignature($key, [
                'alg' => 'HS256',
            ] + $members)
            ->build();
        $token = $serializer->serialize($jws, 0);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(self::TOO_MANY_VALUES);

        $serializer->unserialize($token);
    }

    /**
     * The protected header and the JSON document are decoded with a depth of 512, as by the JSON converter: the token
     * is rejected with the code of the JSON error.
     */
    #[DataProvider('dataTokensNestedTooDeeply')]
    #[Test]
    public function aTokenNestedTooDeeplyIsRejected(JWSSerializer $serializer, string $token): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(self::TOO_DEEP);
        $this->expectExceptionCode(JSON_ERROR_DEPTH);

        $serializer->unserialize($token);
    }

    /**
     * Only the serializer of the format of the token decodes it far enough to reach a bound of the JSON decoder: the
     * manager chains its exception, whatever the order of the serializers. Without such an exception, it chains the
     * exception of the last serializer.
     *
     * @param list<JWSSerializer> $serializers
     */
    #[DataProvider('dataTokensForTheSerializerManager')]
    #[Test]
    public function theSerializerManagerChainsTheExceptionOfTheBound(
        array $serializers,
        string $token,
        string $message
    ): void {
        try {
            (new JWSSerializerManager($serializers))->unserialize($token);
            static::fail('The token should have been rejected.');
        } catch (InvalidSerializationException $e) {
            static::assertSame('Unsupported input.', $e->getMessage());
            static::assertSame(0, $e->getCode());
            static::assertSame($message, $e->getPrevious()?->getMessage());
        }
    }

    #[DataProvider('dataInvalidJsonDocuments')]
    #[Test]
    public function aTokenWhoseJsonIsInvalidIsAnUnsupportedInput(
        JWSSerializer $serializer,
        string $token,
        string $message
    ): void {
        try {
            $serializer->unserialize($token);
            static::fail('The token should have been rejected.');
        } catch (InvalidArgumentException $e) {
            static::assertSame($message, $e->getMessage());
        }
    }

    /**
     * Once decoded, the nested arrays take about a hundred times the size of the token, wherever they are. The
     * threshold is deliberately generous.
     */
    #[DataProvider('dataNestedArrays')]
    #[Test]
    public function aTokenMadeOfNestedArraysIsRejectedWithoutExhaustingMemory(
        JWSSerializer $serializer,
        string $token
    ): void {
        memory_reset_peak_usage();
        $before = memory_get_usage();

        try {
            $serializer->unserialize($token);
            static::fail('The token should have been rejected.');
        } catch (InvalidArgumentException $e) {
            static::assertSame(self::TOO_MANY_VALUES, $e->getMessage());
        }

        static::assertLessThan(8_000_000, memory_get_peak_usage() - $before);
    }

    #[Test]
    public function theProtectedHeadersOfAllSignaturesShareTheBound(): void
    {
        $key = self::createKey();
        $members = array_fill_keys(range(0, 99 * 131072, 131072), 0);
        $builder = $this->getJWSBuilderFactory()
            ->create(['HS256'])
            ->create()
            ->withPayload('{}');
        for ($i = 0; $i < 50; ++$i) {
            $builder = $builder->addSignature($key, [
                'alg' => 'HS256',
            ] + $members);
        }
        $serializer = new JSONGeneralSerializer();
        $token = $serializer->serialize($builder->build());

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(self::TOO_MANY_VALUES);

        $serializer->unserialize($token);
    }

    #[DataProvider('dataJsonSerializers')]
    #[Test]
    public function theContentOfAnUnencodedPayloadIsNotCounted(JWSSerializer $serializer): void
    {
        $key = self::createKey();
        $payload = str_repeat('[{,"\\', BoundedJsonDecoder::MAX_VALUES);
        $jws = $this->getJWSBuilderFactory()
            ->create(['HS256'])
            ->create()
            ->withPayload($payload)
            ->addSignature($key, [
                'alg' => 'HS256',
                'b64' => false,
                'crit' => ['b64'],
            ])
            ->build();

        $loaded = $serializer->unserialize($serializer->serialize($jws, 0));

        static::assertSame($payload, $loaded->getPayload());
        static::assertTrue($this->getJWSVerifierFactory()->create(['HS256'])->verifyWithKey($loaded, $key, 0));
    }

    #[Test]
    public function aTokenWithAHundredSignaturesIsAccepted(): void
    {
        $key = self::createKey();
        $builder = $this->getJWSBuilderFactory()
            ->create(['HS256'])
            ->create()
            ->withPayload('{}');
        for ($i = 0; $i < 100; ++$i) {
            $builder = $builder->addSignature($key, [
                'alg' => 'HS256',
                'kid' => sprintf('key-%d', $i),
            ]);
        }
        $serializer = new JSONGeneralSerializer();

        $loaded = $serializer->unserialize($serializer->serialize($builder->build()));

        static::assertSame(100, $loaded->countSignatures());
        static::assertTrue($this->getJWSVerifierFactory()->create(['HS256'])->verifyWithKey($loaded, $key, 99));
    }

    public static function dataSerializers(): iterable
    {
        yield 'compact' => [new CompactSerializer()];
        yield 'flattened' => [new JSONFlattenedSerializer()];
        yield 'general' => [new JSONGeneralSerializer()];
    }

    public static function dataJsonSerializers(): iterable
    {
        yield 'flattened' => [new JSONFlattenedSerializer()];
        yield 'general' => [new JSONGeneralSerializer()];
    }

    /**
     * Six hundred nested arrays hold far fewer values than the bound.
     *
     * @return iterable<string, array{JWSSerializer, string}>
     */
    public static function dataTokensNestedTooDeeply(): iterable
    {
        $arrays = str_repeat('[', 600) . str_repeat(']', 600);
        $protectedHeader = Base64UrlSafe::encodeUnpadded('{"alg":"HS256"}');
        $deepProtectedHeader = Base64UrlSafe::encodeUnpadded('{"alg":"HS256","x":' . $arrays . '}');
        $signature = Base64UrlSafe::encodeUnpadded(str_repeat("\x01", 32));

        yield 'compact, protected header' => [new CompactSerializer(), $deepProtectedHeader . '.e30.' . $signature];
        yield 'flattened, protected header' => [
            new JSONFlattenedSerializer(),
            sprintf('{"payload":"e30","protected":"%s","signature":"%s"}', $deepProtectedHeader, $signature),
        ];
        yield 'flattened, unprotected header' => [
            new JSONFlattenedSerializer(),
            sprintf(
                '{"payload":"e30","protected":"%s","header":{"x":%s},"signature":"%s"}',
                $protectedHeader,
                $arrays,
                $signature
            ),
        ];
        yield 'general, protected header' => [
            new JSONGeneralSerializer(),
            sprintf(
                '{"payload":"e30","signatures":[{"protected":"%s","signature":"%s"}]}',
                $deepProtectedHeader,
                $signature
            ),
        ];
        yield 'general, unprotected header' => [
            new JSONGeneralSerializer(),
            sprintf(
                '{"payload":"e30","signatures":[{"protected":"%s","header":{"x":%s},"signature":"%s"}]}',
                $protectedHeader,
                $arrays,
                $signature
            ),
        ];
    }

    /**
     * @return iterable<string, array{list<JWSSerializer>, string, string}>
     */
    public static function dataTokensForTheSerializerManager(): iterable
    {
        $compactFirst = [new CompactSerializer(), new JSONFlattenedSerializer(), new JSONGeneralSerializer()];
        $compactLast = [new JSONFlattenedSerializer(), new JSONGeneralSerializer(), new CompactSerializer()];
        $values = '[' . str_repeat('0,', BoundedJsonDecoder::MAX_VALUES) . '0]';
        $arrays = str_repeat('[', 600) . str_repeat(']', 600);
        $manyValues = Base64UrlSafe::encodeUnpadded('{"alg":"HS256","x":' . $values . '}');
        $deep = Base64UrlSafe::encodeUnpadded('{"alg":"HS256","x":' . $arrays . '}');
        $signature = Base64UrlSafe::encodeUnpadded(str_repeat("\x01", 32));
        $flattened = static fn (string $protectedHeader): string => sprintf(
            '{"payload":"e30","protected":"%s","signature":"%s"}',
            $protectedHeader,
            $signature
        );
        $document = sprintf(
            '{"payload":"e30","protected":"%s","header":{"x":%s},"signature":"%s"}',
            Base64UrlSafe::encodeUnpadded('{"alg":"HS256"}'),
            $values,
            $signature
        );

        yield 'compact, too many values, compact first' => [
            $compactFirst,
            $manyValues . '.e30.' . $signature,
            self::TOO_MANY_VALUES,
        ];
        yield 'compact, nested too deeply, compact first' => [
            $compactFirst,
            $deep . '.e30.' . $signature,
            self::TOO_DEEP,
        ];
        yield 'compact, too many values, compact last' => [
            $compactLast,
            $manyValues . '.e30.' . $signature,
            self::TOO_MANY_VALUES,
        ];
        yield 'flattened, protected header with too many values' => [
            $compactFirst,
            $flattened($manyValues),
            self::TOO_MANY_VALUES,
        ];
        yield 'flattened, protected header nested too deeply' => [$compactFirst, $flattened($deep), self::TOO_DEEP];
        yield 'flattened, document with too many values, compact last' => [
            $compactLast,
            $document,
            self::TOO_MANY_VALUES,
        ];
        yield 'not a token: the exception of the last serializer' => [
            $compactFirst,
            'This is not a token',
            'Unsupported input.',
        ];
    }

    /**
     * @return iterable<string, array{JWSSerializer, string, string}>
     */
    public static function dataInvalidJsonDocuments(): iterable
    {
        $signature = Base64UrlSafe::encodeUnpadded(str_repeat("\x01", 32));

        yield 'compact, protected header' => [
            new CompactSerializer(),
            Base64UrlSafe::encodeUnpadded('{"alg":') . '.e30.' . $signature,
            'Unsupported input',
        ];
        yield 'flattened' => [new JSONFlattenedSerializer(), '{"payload":', 'Unsupported input.'];
        yield 'general' => [new JSONGeneralSerializer(), '{"payload":', 'Unsupported input.'];
    }

    public static function dataNestedArrays(): iterable
    {
        $arrays = '[' . str_repeat(str_repeat('[', 500) . str_repeat(']', 500) . ',', 1000) . '0]';
        $protectedHeader = Base64UrlSafe::encodeUnpadded('{"alg":"HS256"}');
        $signature = Base64UrlSafe::encodeUnpadded(str_repeat("\x01", 32));

        yield 'compact, protected header' => [
            new CompactSerializer(),
            Base64UrlSafe::encodeUnpadded('{"alg":"HS256","x":' . $arrays . '}') . '.e30.' . $signature,
        ];
        yield 'flattened, unprotected header' => [
            new JSONFlattenedSerializer(),
            sprintf(
                '{"payload":"e30","protected":"%s","header":{"x":%s},"signature":"%s"}',
                $protectedHeader,
                $arrays,
                $signature
            ),
        ];
        yield 'general, unprotected header' => [
            new JSONGeneralSerializer(),
            sprintf(
                '{"payload":"e30","signatures":[{"protected":"%s","header":{"x":%s},"signature":"%s"}]}',
                $protectedHeader,
                $arrays,
                $signature
            ),
        ];
        yield 'general, member no serializer reads' => [
            new JSONGeneralSerializer(),
            sprintf(
                '{"payload":"e30","x":%s,"signatures":[{"protected":"%s","signature":"%s"}]}',
                $arrays,
                $protectedHeader,
                $signature
            ),
        ];
    }

    private static function createKey(): JWK
    {
        return new JWK([
            'kty' => 'oct',
            'k' => Base64UrlSafe::encodeUnpadded(random_bytes(32)),
        ]);
    }
}
