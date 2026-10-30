<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Encryption;

use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Encryption\JWEDecrypter;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use function chr;

/**
 * @internal
 */
final class AuthenticationTagLengthTest extends EncryptionTestCase
{
    #[DataProvider('dataAlgorithms')]
    #[Test]
    public function tokenWithTruncatedTagIsRejected(string $alg, string $enc, int $keySize): void
    {
        $key = $this->createKey($keySize);
        $decrypter = $this->getJWEDecrypterFactory()
            ->create([$alg, $enc]);
        $token = $this->createToken($alg, $enc, $key);
        $parts = explode('.', $token);
        $tag = Base64UrlSafe::decodeNoPadding($parts[4]);

        static::assertTrue($this->decrypt($decrypter, $token, $key));
        for ($length = 0; $length < 16; ++$length) {
            $parts[4] = Base64UrlSafe::encodeUnpadded(mb_substr($tag, 0, $length, '8bit'));
            static::assertFalse($this->decrypt($decrypter, implode('.', $parts), $key));
        }
    }

    #[DataProvider('dataAlgorithms')]
    #[Test]
    public function tamperedTokenCannotBeForgedWithAOneByteTag(string $alg, string $enc, int $keySize): void
    {
        $key = $this->createKey($keySize);
        $decrypter = $this->getJWEDecrypterFactory()
            ->create([$alg, $enc]);
        $parts = explode('.', $this->createToken($alg, $enc, $key));
        $ciphertext = Base64UrlSafe::decodeNoPadding($parts[3]);
        $parts[3] = Base64UrlSafe::encodeUnpadded(substr_replace($ciphertext, $ciphertext[0] ^ "\x01", 0, 1));

        $accepted = 0;
        for ($byte = 0; $byte < 256; ++$byte) {
            $parts[4] = Base64UrlSafe::encodeUnpadded(chr($byte));
            if ($this->decrypt($decrypter, implode('.', $parts), $key)) {
                ++$accepted;
            }
        }

        static::assertSame(0, $accepted);
    }

    public static function dataAlgorithms(): iterable
    {
        yield 'dir, A128GCM' => ['dir', 'A128GCM', 16];
        yield 'dir, A192GCM' => ['dir', 'A192GCM', 24];
        yield 'dir, A256GCM' => ['dir', 'A256GCM', 32];
        yield 'A256KW, A256GCM' => ['A256KW', 'A256GCM', 32];
        yield 'A256GCMKW, A128GCM' => ['A256GCMKW', 'A128GCM', 32];
    }

    private function createKey(int $size): JWK
    {
        return new JWK([
            'kty' => 'oct',
            'k' => Base64UrlSafe::encodeUnpadded(random_bytes($size)),
        ]);
    }

    private function createToken(string $alg, string $enc, JWK $key): string
    {
        $jwe = $this->getJWEBuilderFactory()
            ->create([$alg, $enc])
            ->create()
            ->withPayload('{"sub":"alice","adm":0}')
            ->withSharedProtectedHeader([
                'alg' => $alg,
                'enc' => $enc,
            ])
            ->addRecipient($key)
            ->build();

        return $this->getJWESerializerManager()
            ->serialize('jwe_compact', $jwe, 0);
    }

    private function decrypt(JWEDecrypter $decrypter, string $token, JWK $key): bool
    {
        $jwe = $this->getJWESerializerManager()
            ->unserialize($token);

        return $decrypter->decryptUsingKey($jwe, $key, 0);
    }
}
