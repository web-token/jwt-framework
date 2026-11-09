<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Encryption;

use InvalidArgumentException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Core\Util\BoundedJsonDecoder;
use Jose\Component\Encryption\Serializer\CompactSerializer;
use Jose\Component\Encryption\Serializer\JSONFlattenedSerializer;
use Jose\Component\Encryption\Serializer\JSONGeneralSerializer;
use Jose\Component\Encryption\Serializer\JWESerializer;
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
final class JsonValueBoundTest extends EncryptionTestCase
{
    private const TOO_MANY_VALUES = 'The JSON documents of the token hold more JSON values than the 4096 that are decoded.';

    private const TOO_DEEP = 'A JSON document of the token is nested too deeply.';

    /**
     * The member names are multiples of 131072: they all fall into the first bucket of a PHP array.
     */
    #[DataProvider('dataSerializers')]
    #[Test]
    public function anEncryptedTokenWhoseProtectedHeaderHoldsTooManyMembersIsRejected(JWESerializer $serializer): void
    {
        $jwe = $this->getJWEBuilderFactory()
            ->create(['A128KW', 'A128GCM'])
            ->create()
            ->withPayload('{}')
            ->withSharedProtectedHeader([
                'alg' => 'A128KW',
                'enc' => 'A128GCM',
            ] + self::tooManyMembers())
            ->addRecipient(self::createKey())
            ->build();
        $token = $serializer->serialize($jwe, 0);

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
    public function aTokenNestedTooDeeplyIsRejected(JWESerializer $serializer, string $token): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(self::TOO_DEEP);
        $this->expectExceptionCode(JSON_ERROR_DEPTH);

        $serializer->unserialize($token);
    }

    #[DataProvider('dataInvalidJsonDocuments')]
    #[Test]
    public function aTokenWhoseJsonIsInvalidIsAnUnsupportedInput(
        JWESerializer $serializer,
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

    #[DataProvider('dataJsonSerializers')]
    #[Test]
    public function anEncryptedTokenWhoseUnprotectedHeaderHoldsTooManyMembersIsRejected(
        JWESerializer $serializer
    ): void {
        $jwe = $this->getJWEBuilderFactory()
            ->create(['A128KW', 'A128GCM'])
            ->create()
            ->withPayload('{}')
            ->withSharedProtectedHeader([
                'alg' => 'A128KW',
                'enc' => 'A128GCM',
            ])
            ->withSharedHeader(self::tooManyMembers())
            ->addRecipient(self::createKey())
            ->build();
        $token = $serializer->serialize($jwe, 0);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(self::TOO_MANY_VALUES);

        $serializer->unserialize($token);
    }

    /**
     * Once decoded, the nested arrays take about a hundred times the size of the token. The threshold is deliberately
     * generous.
     */
    #[Test]
    public function aTokenMadeOfNestedArraysIsRejectedWithoutExhaustingMemory(): void
    {
        $arrays = '[' . str_repeat(str_repeat('[', 500) . str_repeat(']', 500) . ',', 1000) . '0]';
        $token = Base64UrlSafe::encodeUnpadded('{"alg":"A128KW","enc":"A128GCM","x":' . $arrays . '}') . '....';
        $serializer = new CompactSerializer();
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
    public function aTokenWithAHundredRecipientsIsAccepted(): void
    {
        $keys = [];
        $builder = $this->getJWEBuilderFactory()
            ->create(['A128KW', 'A128GCM'])
            ->create()
            ->withPayload('{"foo":"bar"}')
            ->withSharedProtectedHeader([
                'enc' => 'A128GCM',
            ]);
        for ($i = 0; $i < 100; ++$i) {
            $keys[$i] = self::createKey();
            $builder = $builder->addRecipient($keys[$i], [
                'alg' => 'A128KW',
                'kid' => sprintf('key-%d', $i),
            ]);
        }
        $serializer = new JSONGeneralSerializer();

        $jwe = $serializer->unserialize($serializer->serialize($builder->build()));

        static::assertSame(100, $jwe->countRecipients());
        $result = $this->getJWEDecrypterFactory()
            ->create(['A128KW', 'A128GCM'])
            ->decrypt($jwe, $keys[99], 99);
        static::assertTrue($result->isDecrypted());
        static::assertSame('{"foo":"bar"}', $result->getJwe()->getPayload());
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
     * @return iterable<string, array{JWESerializer, string}>
     */
    public static function dataTokensNestedTooDeeply(): iterable
    {
        $arrays = str_repeat('[', 600) . str_repeat(']', 600);
        $protectedHeader = Base64UrlSafe::encodeUnpadded('{"alg":"A128KW","enc":"A128GCM"}');
        $deepProtectedHeader = Base64UrlSafe::encodeUnpadded('{"alg":"A128KW","enc":"A128GCM","x":' . $arrays . '}');
        $parts = '"iv":"AAAA","ciphertext":"AAAA","tag":"AAAA"';

        yield 'compact, protected header' => [new CompactSerializer(), $deepProtectedHeader . '.AAAA.AAAA.AAAA.AAAA'];
        yield 'flattened, protected header' => [
            new JSONFlattenedSerializer(),
            sprintf('{"protected":"%s","encrypted_key":"AAAA",%s}', $deepProtectedHeader, $parts),
        ];
        yield 'flattened, unprotected header' => [
            new JSONFlattenedSerializer(),
            sprintf(
                '{"protected":"%s","unprotected":{"x":%s},"encrypted_key":"AAAA",%s}',
                $protectedHeader,
                $arrays,
                $parts
            ),
        ];
        yield 'general, protected header' => [
            new JSONGeneralSerializer(),
            sprintf('{"protected":"%s","recipients":[{"encrypted_key":"AAAA"}],%s}', $deepProtectedHeader, $parts),
        ];
        yield 'general, unprotected header' => [
            new JSONGeneralSerializer(),
            sprintf(
                '{"protected":"%s","unprotected":{"x":%s},"recipients":[{"encrypted_key":"AAAA"}],%s}',
                $protectedHeader,
                $arrays,
                $parts
            ),
        ];
    }

    /**
     * @return iterable<string, array{JWESerializer, string, string}>
     */
    public static function dataInvalidJsonDocuments(): iterable
    {
        yield 'compact, protected header' => [
            new CompactSerializer(),
            Base64UrlSafe::encodeUnpadded('{"alg":') . '.AAAA.AAAA.AAAA.AAAA',
            'Unsupported input',
        ];
        yield 'flattened' => [new JSONFlattenedSerializer(), '{"protected":', 'Unsupported input.'];
        yield 'general' => [new JSONGeneralSerializer(), '{"protected":', 'Unsupported input.'];
    }

    /**
     * @return array<int, int>
     */
    private static function tooManyMembers(): array
    {
        return array_fill_keys(range(0, (BoundedJsonDecoder::MAX_VALUES - 1) * 131072, 131072), 0);
    }

    private static function createKey(): JWK
    {
        return new JWK([
            'kty' => 'oct',
            'k' => Base64UrlSafe::encodeUnpadded(random_bytes(16)),
        ]);
    }
}
