<?php

declare(strict_types=1);

namespace Jose\Tests\EncryptionAlgorithm\Experimental;

use InvalidArgumentException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Encryption\Algorithm\KeyEncryption\KeyEncryption;
use Jose\Experimental\KeyEncryption\A128CTR;
use Jose\Experimental\KeyEncryption\A192CTR;
use Jose\Experimental\KeyEncryption\A256CTR;
use Jose\Experimental\KeyEncryption\Chacha20Poly1305;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function in_array;
use function sprintf;

/**
 * @internal
 */
final class KeyEncryptionKeyLengthTest extends TestCase
{
    #[DataProvider('dataAlgorithms')]
    #[Test]
    public function keyOfTheAlgorithmSizeIsAccepted(string $alg, int $keySize): void
    {
        $algorithm = $this->createAlgorithm($alg);
        $key = $this->createKey(random_bytes($keySize));
        $cek = random_bytes(32);

        $header = [];
        $encryptedKey = $algorithm->encryptKey($key, $cek, [], $header);

        static::assertSame($cek, $algorithm->decryptKey($key, $encryptedKey, $header));
    }

    #[DataProvider('dataAlgorithms')]
    #[Test]
    public function shorterKeyIsRejected(string $alg, int $keySize): void
    {
        $algorithm = $this->createAlgorithm($alg);
        for ($length = 0; $length < $keySize; ++$length) {
            $shorterKey = mb_substr(random_bytes($keySize), 0, $length, '8bit');
            $header = [];
            $encryptedKey = $algorithm->encryptKey(
                $this->createKey(str_pad($shorterKey, $keySize, "\0")),
                random_bytes(32),
                [],
                $header
            );
            try {
                $algorithm->encryptKey($this->createKey($shorterKey), random_bytes(32), [], $header);
                static::fail(sprintf('A key of %d bytes was accepted for encryption.', $length));
            } catch (InvalidArgumentException $e) {
                static::assertSame('Invalid key length.', $e->getMessage());
            }
            try {
                $algorithm->decryptKey($this->createKey($shorterKey), $encryptedKey, $header);
                static::fail(sprintf('A key of %d bytes was accepted for decryption.', $length));
            } catch (InvalidArgumentException $e) {
                static::assertSame('Invalid key length.', $e->getMessage());
            }
        }
    }

    #[DataProvider('dataAlgorithms')]
    #[Test]
    public function longerKeyIsStillAccepted(string $alg, int $keySize): void
    {
        $algorithm = $this->createAlgorithm($alg);
        $key = $this->createKey(random_bytes($keySize + 16));
        $cek = random_bytes(32);

        $header = [];
        $encryptedKey = $algorithm->encryptKey($key, $cek, [], $header);

        static::assertSame($cek, $algorithm->decryptKey($key, $encryptedKey, $header));
    }

    public static function dataAlgorithms(): iterable
    {
        yield 'A128CTR' => ['A128CTR', 16];
        yield 'A192CTR' => ['A192CTR', 24];
        yield 'A256CTR' => ['A256CTR', 32];
        yield 'chacha20-poly1305' => ['chacha20-poly1305', 32];
    }

    private function createAlgorithm(string $alg): KeyEncryption
    {
        if ($alg === 'chacha20-poly1305' && ! in_array('chacha20-poly1305', openssl_get_cipher_methods(), true)) {
            static::markTestSkipped('The algorithm "chacha20-poly1305" is not supported on this platform.');
        }

        return match ($alg) {
            'A128CTR' => new A128CTR(),
            'A192CTR' => new A192CTR(),
            'A256CTR' => new A256CTR(),
            default => new Chacha20Poly1305(),
        };
    }

    private function createKey(string $k): JWK
    {
        return new JWK([
            'kty' => 'oct',
            'k' => Base64UrlSafe::encodeUnpadded($k),
        ]);
    }
}
