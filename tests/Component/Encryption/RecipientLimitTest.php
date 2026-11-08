<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Encryption;

use InvalidArgumentException;
use Jose\Component\Checker\HeaderChecker;
use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\Encryption\JWELoader;
use Jose\Component\Encryption\JWETokenSupport;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use RuntimeException;

/**
 * @internal
 */
final class RecipientLimitTest extends EncryptionTestCase
{
    #[Test]
    public function aTokenWithMoreRecipientsThanTheLimitIsRejectedBeforeAnyRecipientIsProcessed(): void
    {
        $checker = new class() implements HeaderChecker {
            public int $calls = 0;

            public function checkHeader(mixed $value): void
            {
                ++$this->calls;
            }

            public function supportedHeader(): string
            {
                return 'alg';
            }

            public function protectedHeaderOnly(): bool
            {
                return false;
            }
        };
        $jweLoader = $this->createJWELoader(10, $checker);
        $key = $this->createKey();

        $this->assertRejected($jweLoader, $this->createTokenWithForgedRecipients(11), $key);
        static::assertSame(0, $checker->calls);

        $this->assertRejected($jweLoader, $this->createTokenWithForgedRecipients(10), $key);
        static::assertSame(10, $checker->calls);
    }

    #[Test]
    public function aTokenWithAsManyRecipientsAsTheLimitIsDecrypted(): void
    {
        $keys = $this->createKeys(10);

        $jwe = $this->createJWELoader(10)
            ->loadAndDecryptWithKey($this->createToken($keys), $keys[9], $recipient);

        static::assertSame(9, $recipient);
        static::assertSame('Live long and prosper.', $jwe->getPayload());
    }

    #[Test]
    public function withoutALimitEveryRecipientIsTried(): void
    {
        $keys = $this->createKeys(11);

        $jwe = $this->createJWELoader(null)
            ->loadAndDecryptWithKey($this->createToken($keys), $keys[10], $recipient);

        static::assertSame(10, $recipient);
        static::assertSame('Live long and prosper.', $jwe->getPayload());
    }

    #[DataProvider('dataInvalidLimits')]
    #[Test]
    public function anInvalidLimitIsRefused(mixed $limit): void
    {
        $loader = $this->getJWELoaderFactory()
            ->create(['jwe_json_general'], ['A128KW', 'A128GCM']);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The maximum number of recipients must be a positive integer.');

        new JWELoader($loader->getSerializerManager(), $loader->getJweDecrypter(), null, $limit);
    }

    public static function dataInvalidLimits(): iterable
    {
        yield 'zero' => [0];
        yield 'negative' => [-1];
        yield 'string' => ['10'];
    }

    private function createJWELoader(?int $maxRecipients, ?HeaderChecker $checker = null): JWELoader
    {
        $jweLoader = $this->getJWELoaderFactory()
            ->create(['jwe_json_general'], ['A128KW', 'A128GCM']);

        return new JWELoader(
            $jweLoader->getSerializerManager(),
            $jweLoader->getJweDecrypter(),
            $checker === null ? null : new HeaderCheckerManager([$checker], [new JWETokenSupport()]),
            $maxRecipients
        );
    }

    private function createTokenWithForgedRecipients(int $count): string
    {
        return JsonConverter::encode([
            'protected' => Base64UrlSafe::encodeUnpadded(JsonConverter::encode([
                'alg' => 'A128KW',
                'enc' => 'A128GCM',
            ])),
            'iv' => Base64UrlSafe::encodeUnpadded(str_repeat("\0", 12)),
            'ciphertext' => Base64UrlSafe::encodeUnpadded('anything'),
            'tag' => Base64UrlSafe::encodeUnpadded(str_repeat("\0", 16)),
            'recipients' => array_fill(0, $count, [
                'encrypted_key' => Base64UrlSafe::encodeUnpadded(str_repeat("\0", 24)),
            ]),
        ]);
    }

    /**
     * @param JWK[] $keys
     */
    private function createToken(array $keys): string
    {
        $jweBuilder = $this->getJWEBuilderFactory()
            ->create(['A128KW', 'A128GCM'])
            ->create()
            ->withPayload('Live long and prosper.')
            ->withSharedProtectedHeader([
                'alg' => 'A128KW',
                'enc' => 'A128GCM',
            ]);
        foreach ($keys as $key) {
            $jweBuilder = $jweBuilder->addRecipient($key);
        }

        return $this->getJWESerializerManager()
            ->serialize('jwe_json_general', $jweBuilder->build());
    }

    /**
     * @return JWK[]
     */
    private function createKeys(int $count): array
    {
        $keys = [];
        for ($i = 0; $i < $count; ++$i) {
            $keys[] = $this->createKey();
        }

        return $keys;
    }

    private function createKey(): JWK
    {
        return new JWK([
            'kty' => 'oct',
            'k' => Base64UrlSafe::encodeUnpadded(random_bytes(16)),
        ]);
    }

    private function assertRejected(JWELoader $jweLoader, string $token, JWK $key): void
    {
        try {
            $jweLoader->loadAndDecryptWithKey($token, $key, $recipient);
        } catch (RuntimeException $exception) {
            static::assertSame('Unable to load and decrypt the token.', $exception->getMessage());

            return;
        }
        static::fail('The token has been decrypted.');
    }
}
