<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Encryption;

use InvalidArgumentException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Encryption\JWEDecrypter;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use function sprintf;

/**
 * @internal
 */
final class KeyEncryptionKeyLengthTest extends EncryptionTestCase
{
    #[DataProvider('dataAlgorithms')]
    #[Test]
    public function keyOfTheAlgorithmSizeIsAccepted(string $alg, int $keySize): void
    {
        $key = $this->createKey(random_bytes($keySize));
        $token = $this->createToken($this->createBuilder($alg), $alg, $key);

        static::assertTrue($this->decrypt($this->createDecrypter($alg), $token, $key));
    }

    #[DataProvider('dataAlgorithms')]
    #[Test]
    public function shorterKeyCannotWrapTheCek(string $alg, int $keySize): void
    {
        $builder = $this->createBuilder($alg);
        for ($length = 0; $length < $keySize; ++$length) {
            $key = $this->createKey(mb_substr(random_bytes($keySize), 0, $length, '8bit'));
            try {
                $this->createToken($builder, $alg, $key);
                static::fail(sprintf('A key of %d bytes was accepted.', $length));
            } catch (InvalidArgumentException $e) {
                static::assertSame('Invalid key length.', $e->getMessage());
            }
        }
    }

    #[DataProvider('dataAlgorithms')]
    #[Test]
    public function shorterKeyCannotUnwrapTheCekWrappedWithItsZeroPaddedValue(string $alg, int $keySize): void
    {
        $builder = $this->createBuilder($alg);
        $decrypter = $this->createDecrypter($alg);
        for ($length = 0; $length < $keySize; ++$length) {
            $shorterKey = mb_substr(random_bytes($keySize), 0, $length, '8bit');
            $token = $this->createToken($builder, $alg, $this->createKey(str_pad($shorterKey, $keySize, "\0")));

            static::assertFalse($this->decrypt($decrypter, $token, $this->createKey($shorterKey)));
        }
    }

    #[DataProvider('dataAlgorithms')]
    #[Test]
    public function keySetHoldingAShorterKeyStillDecrypts(string $alg, int $keySize): void
    {
        $key = $this->createKey(random_bytes($keySize));
        $keySet = new JWKSet([$this->createKey(random_bytes($keySize - 1)), $key]);
        $jwe = $this->getJWESerializerManager()
            ->unserialize($this->createToken($this->createBuilder($alg), $alg, $key));

        static::assertTrue($this->createDecrypter($alg)->decryptUsingKeySet($jwe, $keySet, 0));
    }

    #[DataProvider('dataAlgorithms')]
    #[Test]
    public function longerKeyIsStillAccepted(string $alg, int $keySize): void
    {
        $key = $this->createKey(random_bytes($keySize + 16));
        $token = $this->createToken($this->createBuilder($alg), $alg, $key);

        static::assertTrue($this->decrypt($this->createDecrypter($alg), $token, $key));
    }

    public static function dataAlgorithms(): iterable
    {
        yield 'A128KW' => ['A128KW', 16];
        yield 'A192KW' => ['A192KW', 24];
        yield 'A256KW' => ['A256KW', 32];
        yield 'A128GCMKW' => ['A128GCMKW', 16];
        yield 'A192GCMKW' => ['A192GCMKW', 24];
        yield 'A256GCMKW' => ['A256GCMKW', 32];
    }

    private function createKey(string $k): JWK
    {
        return new JWK([
            'kty' => 'oct',
            'k' => Base64UrlSafe::encodeUnpadded($k),
        ]);
    }

    private function createBuilder(string $alg): JWEBuilder
    {
        return $this->getJWEBuilderFactory()
            ->create([$alg, 'A128GCM']);
    }

    private function createDecrypter(string $alg): JWEDecrypter
    {
        return $this->getJWEDecrypterFactory()
            ->create([$alg, 'A128GCM']);
    }

    private function createToken(JWEBuilder $builder, string $alg, JWK $key): string
    {
        $jwe = $builder
            ->create()
            ->withPayload('{"sub":"alice","adm":0}')
            ->withSharedProtectedHeader([
                'alg' => $alg,
                'enc' => 'A128GCM',
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
