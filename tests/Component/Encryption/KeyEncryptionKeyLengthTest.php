<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Encryption;

use Jose\Component\Core\Exception\InvalidKeyException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Encryption\JWEDecrypter;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use function set_error_handler;
use function sprintf;
use const E_USER_DEPRECATED;

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
        $builder = $this->createBuilder($alg);
        $decrypter = $this->createDecrypter($alg);

        $deprecations = $this->collectDeprecations(function () use ($alg, $key, $builder, $decrypter): void {
            static::assertTrue($this->decrypt($decrypter, $this->createToken($builder, $alg, $key), $key));
        });

        static::assertSame([], $deprecations);
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
            } catch (InvalidKeyException $e) {
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
        $token = $this->createToken($this->createBuilder($alg), $alg, $key);
        $keySet = new JWKSet([$this->createKey(random_bytes($keySize - 1)), $key]);

        static::assertTrue($this->decrypt($this->createDecrypter($alg), $token, $keySet));
    }

    #[DataProvider('dataAlgorithms')]
    #[Test]
    public function longerKeyIsStillAcceptedButDeprecated(string $alg, int $keySize): void
    {
        $key = $this->createKey(random_bytes($keySize + 16));
        $builder = $this->createBuilder($alg);
        $decrypter = $this->createDecrypter($alg);

        $deprecations = $this->collectDeprecations(function () use ($alg, $key, $builder, $decrypter): void {
            static::assertTrue($this->decrypt($decrypter, $this->createToken($builder, $alg, $key), $key));
        });

        $message = sprintf(
            'Since web-token/jwt-library 4.3.0: Using a key of %d bits with "%s" is deprecated and will not be possible in 5.0.0: the key must have exactly %d bits.',
            ($keySize + 16) * 8,
            $alg,
            $keySize * 8
        );
        static::assertSame([$message, $message], $deprecations);
    }

    #[DataProvider('dataAlgorithms')]
    #[Test]
    public function longerKeyThatDoesNotProtectTheTokenIsNotReported(string $alg, int $keySize): void
    {
        $key = $this->createKey(random_bytes($keySize));
        $token = $this->createToken($this->createBuilder($alg), $alg, $key);
        $keySet = new JWKSet([$this->createKey(random_bytes($keySize + 16)), $key]);
        $decrypter = $this->createDecrypter($alg);

        $deprecations = $this->collectDeprecations(function () use ($decrypter, $token, $keySet): void {
            static::assertTrue($this->decrypt($decrypter, $token, $keySet));
        });

        static::assertSame([], $deprecations);
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

    /**
     * @param callable(): void $callback
     *
     * @return list<string>
     */
    private function collectDeprecations(callable $callback): array
    {
        $deprecations = [];
        set_error_handler(static function (int $errno, string $errstr) use (&$deprecations): bool {
            $deprecations[] = $errstr;

            return true;
        }, E_USER_DEPRECATED);

        try {
            $callback();
        } finally {
            restore_error_handler();
        }

        return $deprecations;
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

    private function decrypt(JWEDecrypter $decrypter, string $token, JWK|JWKSet $keys): bool
    {
        return $decrypter->decrypt($this->getJWESerializerManager()->unserialize($token), $keys, 0)->isDecrypted();
    }
}
