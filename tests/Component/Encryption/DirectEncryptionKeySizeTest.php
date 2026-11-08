<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Encryption;

use InvalidArgumentException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\Encryption\Algorithm\ContentEncryptionAlgorithm;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use function intdiv;

/**
 * With "dir", the key is the CEK. AES-CBC-HMAC takes its MAC key from the first half and its AES key from the second
 * half, and OpenSSL pads a short AES key with zero bytes and ignores the end of a long one.
 *
 * @internal
 */
final class DirectEncryptionKeySizeTest extends EncryptionTestCase
{
    private const PAYLOAD = 'Live long and Prosper.';

    #[DataProvider('keysOfAnotherSize')]
    #[Test]
    public function theBuilderRefusesADirectKeyOfAnotherSizeThanTheContentEncryptionKey(string $enc, int $keyLength): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid CEK size');

        $this->build($enc, $this->createKey($keyLength));
    }

    /**
     * The tokens are encrypted the way the builder did before it checked the key. With an empty key, anyone can make
     * them.
     */
    #[DataProvider('keysOfAnotherSize')]
    #[Test]
    public function theDecrypterRefusesADirectKeyOfAnotherSizeThanTheContentEncryptionKey(string $enc, int $keyLength): void
    {
        $key = $this->createKey($keyLength);

        static::assertNull($this->decrypt($enc, $this->encryptContent($enc, $key), $key));
    }

    #[DataProvider('exactKeys')]
    #[Test]
    public function aDirectKeyOfTheContentEncryptionKeySizeIsAccepted(string $enc, int $keyLength): void
    {
        $key = $this->createKey($keyLength);

        static::assertSame(self::PAYLOAD, $this->decrypt($enc, $this->build($enc, $key), $key));
        static::assertSame(self::PAYLOAD, $this->decrypt($enc, $this->encryptContent($enc, $key), $key));
    }

    /**
     * A token issued by 4.x with a longer key is decrypted with the first bytes of that key, as many as the content
     * encryption key has.
     */
    #[DataProvider('longerKeys')]
    #[Test]
    public function aTokenIssuedWithALongerKeyIsDecryptedWithItsFirstBytes(string $enc, int $keyLength): void
    {
        $key = $this->createKey($keyLength);
        $algorithm = $this->getAlgorithmManagerFactory()
            ->create([$enc])
            ->get($enc);
        static::assertInstanceOf(ContentEncryptionAlgorithm::class, $algorithm);
        $truncatedKey = new JWK([
            'kty' => 'oct',
            'k' => Base64UrlSafe::encodeUnpadded(substr(
                Base64UrlSafe::decodeNoPadding((string) $key->get('k')),
                0,
                intdiv($algorithm->getCEKSize(), 8)
            )),
        ]);

        static::assertSame(self::PAYLOAD, $this->decrypt($enc, $this->encryptContent($enc, $key), $truncatedKey));
    }

    #[Test]
    public function theKeyOfTheRightSizeIsFoundInAKeySet(): void
    {
        $key = $this->createKey(32);
        $token = $this->encryptContent('A256GCM', $key);

        static::assertSame(
            self::PAYLOAD,
            $this->decrypt('A256GCM', $token, new JWKSet([$this->createKey(64), $this->createKey(16), $key]))
        );
    }

    /**
     * @return iterable<string, array{string, int}>
     */
    public static function keysOfAnotherSize(): iterable
    {
        yield 'A128CBC-HS256, 16 bytes, all-zero AES key' => ['A128CBC-HS256', 16];
        yield 'A192CBC-HS384, 24 bytes, all-zero AES key' => ['A192CBC-HS384', 24];
        yield 'A256CBC-HS512, 32 bytes, all-zero AES key' => ['A256CBC-HS512', 32];
        yield 'A192CBC-HS384, 32 bytes, 8 secret AES key bytes' => ['A192CBC-HS384', 32];
        yield 'A256CBC-HS512, 48 bytes, 16 secret AES key bytes' => ['A256CBC-HS512', 48];
        yield 'A128CBC-HS256, 31 bytes' => ['A128CBC-HS256', 31];
        yield 'A128CBC-HS256, empty key' => ['A128CBC-HS256', 0];
        yield 'A128GCM, 15 bytes' => ['A128GCM', 15];
        yield 'A256GCM, 16 bytes' => ['A256GCM', 16];
        yield 'A128GCM, empty key' => ['A128GCM', 0];
        yield 'A128CBC-HS256, 64 bytes' => ['A128CBC-HS256', 64];
        yield 'A128CBC-HS256, 33 bytes' => ['A128CBC-HS256', 33];
        yield 'A128GCM, 32 bytes' => ['A128GCM', 32];
        yield 'A256GCM, 33 bytes' => ['A256GCM', 33];
    }

    /**
     * @return iterable<string, array{string, int}>
     */
    public static function exactKeys(): iterable
    {
        yield 'A128CBC-HS256, 32 bytes' => ['A128CBC-HS256', 32];
        yield 'A192CBC-HS384, 48 bytes' => ['A192CBC-HS384', 48];
        yield 'A256CBC-HS512, 64 bytes' => ['A256CBC-HS512', 64];
        yield 'A128GCM, 16 bytes' => ['A128GCM', 16];
        yield 'A192GCM, 24 bytes' => ['A192GCM', 24];
        yield 'A256GCM, 32 bytes' => ['A256GCM', 32];
    }

    /**
     * @return iterable<string, array{string, int}>
     */
    public static function longerKeys(): iterable
    {
        yield 'A128CBC-HS256, 64 bytes' => ['A128CBC-HS256', 64];
        yield 'A192CBC-HS384, 49 bytes' => ['A192CBC-HS384', 49];
        yield 'A128GCM, 32 bytes' => ['A128GCM', 32];
        yield 'A256GCM, 33 bytes' => ['A256GCM', 33];
    }

    private function createKey(int $length): JWK
    {
        return new JWK([
            'kty' => 'oct',
            'k' => Base64UrlSafe::encodeUnpadded($length === 0 ? '' : random_bytes($length)),
        ]);
    }

    private function build(string $enc, JWK $key): string
    {
        $jwe = $this->getJWEBuilderFactory()
            ->create(['dir', $enc])
            ->withPayload(self::PAYLOAD)
            ->withSharedProtectedHeader([
                'alg' => 'dir',
                'enc' => $enc,
            ])
            ->addRecipient($key)
            ->build();

        return $this->getJWESerializerManager()
            ->serialize('jwe_compact', $jwe, 0);
    }

    private function encryptContent(string $enc, JWK $key): string
    {
        $algorithm = $this->getAlgorithmManagerFactory()
            ->create([$enc])
            ->get($enc);
        static::assertInstanceOf(ContentEncryptionAlgorithm::class, $algorithm);
        $header = Base64UrlSafe::encodeUnpadded(JsonConverter::encode([
            'alg' => 'dir',
            'enc' => $enc,
        ]));
        $iv = random_bytes(intdiv($algorithm->getIVSize(), 8));
        $tag = null;
        $ciphertext = $algorithm->encryptContent(
            self::PAYLOAD,
            Base64UrlSafe::decodeNoPadding((string) $key->get('k')),
            $iv,
            null,
            $header,
            $tag
        );

        return implode('.', [
            $header,
            '',
            Base64UrlSafe::encodeUnpadded($iv),
            Base64UrlSafe::encodeUnpadded($ciphertext),
            Base64UrlSafe::encodeUnpadded((string) $tag),
        ]);
    }

    private function decrypt(string $enc, string $token, JWK|JWKSet $keys): ?string
    {
        $result = $this->getJWEDecrypterFactory()
            ->create(['dir', $enc])
            ->decrypt($this->getJWESerializerManager()->unserialize($token), $keys, 0);

        return $result->isDecrypted() ? $result->getJwe()
            ->getPayload() : null;
    }
}
