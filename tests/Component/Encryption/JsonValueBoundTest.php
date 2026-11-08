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

/**
 * @internal
 */
final class JsonValueBoundTest extends EncryptionTestCase
{
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
        $this->expectExceptionMessage('Unsupported input');

        $serializer->unserialize($token);
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
        $this->expectExceptionMessage('Unsupported input.');

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
            static::assertStringStartsWith('Unsupported input', $e->getMessage());
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
        static::assertTrue(
            $this->getJWEDecrypterFactory()
                ->create(['A128KW', 'A128GCM'])
                ->decryptUsingKey($jwe, $keys[99], 99)
        );
        static::assertSame('{"foo":"bar"}', $jwe->getPayload());
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
