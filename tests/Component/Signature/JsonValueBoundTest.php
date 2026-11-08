<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Signature;

use InvalidArgumentException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Core\Util\BoundedJsonDecoder;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JSONFlattenedSerializer;
use Jose\Component\Signature\Serializer\JSONGeneralSerializer;
use Jose\Component\Signature\Serializer\JWSSerializer;
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

/**
 * @internal
 */
final class JsonValueBoundTest extends SignatureTestCase
{
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
        $this->expectExceptionMessage('Unsupported input');

        $serializer->unserialize($token);
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
            static::assertStringStartsWith('Unsupported input', $e->getMessage());
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
        $this->expectExceptionMessage('Unsupported input.');

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
