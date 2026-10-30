<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Encryption;

use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\Encryption\JWE;
use Jose\Component\Encryption\Recipient;
use Jose\Component\Encryption\Serializer\JSONFlattenedSerializer;
use Jose\Component\Encryption\Serializer\JSONGeneralSerializer;
use Jose\Component\Encryption\Serializer\JWESerializer;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The "iv" and "tag" members of the JWE JSON Serialization are absent when the IV or the tag is the empty octet
 * sequence (RFC 7516 section 7.2.1), as in the Integrated Encryption of draft-ietf-jose-hpke-encrypt.
 *
 * @internal
 */
final class EmptyInitializationVectorAndTagTest extends TestCase
{
    /**
     * @return iterable<string, array{JWESerializer}>
     */
    public static function serializers(): iterable
    {
        yield 'JSON Flattened' => [new JSONFlattenedSerializer()];
        yield 'JSON General' => [new JSONGeneralSerializer()];
    }

    #[Test]
    #[DataProvider('serializers')]
    public function theEmptyMembersAreOmitted(JWESerializer $serializer): void
    {
        $members = JsonConverter::decode($serializer->serialize($this->jwe('', ''), 0));

        static::assertIsArray($members);
        static::assertArrayNotHasKey('iv', $members);
        static::assertArrayNotHasKey('tag', $members);
        static::assertSame(Base64UrlSafe::encodeUnpadded('ciphertext'), $members['ciphertext']);
    }

    #[Test]
    #[DataProvider('serializers')]
    public function theOtherMembersAreKept(JWESerializer $serializer): void
    {
        $members = JsonConverter::decode($serializer->serialize($this->jwe('initialization', 'tag'), 0));

        static::assertIsArray($members);
        static::assertSame(Base64UrlSafe::encodeUnpadded('initialization'), $members['iv']);
        static::assertSame(Base64UrlSafe::encodeUnpadded('tag'), $members['tag']);
    }

    #[Test]
    #[DataProvider('serializers')]
    public function theAbsentMembersAreEmpty(JWESerializer $serializer): void
    {
        $members = [
            'protected' => Base64UrlSafe::encodeUnpadded(JsonConverter::encode([
                'alg' => 'HPKE-0',
            ])),
            'ciphertext' => Base64UrlSafe::encodeUnpadded('ciphertext'),
        ];
        $recipient = [
            'encrypted_key' => Base64UrlSafe::encodeUnpadded('encrypted key'),
        ];
        $input = $serializer instanceof JSONGeneralSerializer ? $members + [
            'recipients' => [$recipient],
        ] : $members + $recipient;

        $jwe = $serializer->unserialize(JsonConverter::encode($input));

        static::assertSame('', $jwe->getIV());
        static::assertSame('', $jwe->getTag());
        static::assertSame('ciphertext', $jwe->getCiphertext());
        static::assertSame('encrypted key', $jwe->getRecipient(0)->getEncryptedKey());
    }

    private function jwe(string $iv, string $tag): JWE
    {
        $header = [
            'alg' => 'HPKE-0',
        ];

        return new JWE(
            'ciphertext',
            $iv,
            $tag,
            null,
            [],
            $header,
            Base64UrlSafe::encodeUnpadded(JsonConverter::encode($header)),
            [new Recipient([], 'encrypted key')]
        );
    }
}
