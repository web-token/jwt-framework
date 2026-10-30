<?php

declare(strict_types=1);

namespace Jose\Tests\EncryptionAlgorithm\Experimental;

use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Experimental\ContentEncryption\A128CCM_16_128;
use Jose\Experimental\ContentEncryption\A128CCM_16_64;
use Jose\Experimental\ContentEncryption\A128CCM_64_128;
use Jose\Experimental\ContentEncryption\A128CCM_64_64;
use Jose\Experimental\ContentEncryption\A256CCM_16_128;
use Jose\Experimental\ContentEncryption\A256CCM_16_64;
use Jose\Experimental\ContentEncryption\A256CCM_64_128;
use Jose\Experimental\ContentEncryption\A256CCM_64_64;
use Jose\Experimental\ContentEncryption\AESCCM;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use function in_array;
use function sprintf;
use const OPENSSL_RAW_DATA;

/**
 * @internal
 */
final class AESCCMContentEncryptionTest extends TestCase
{
    protected function setUp(): void
    {
        if (! in_array('aes-128-ccm', openssl_get_cipher_methods(), true)) {
            static::markTestSkipped('The algorithm "aes-128-ccm" is not supported on this platform.');
        }
    }

    #[DataProvider('dataAlgorithms')]
    #[Test]
    public function encryptAndDecrypt(AESCCM $algorithm, int $tagLength): void
    {
        $header = $this->header($algorithm);
        $cek = random_bytes($algorithm->getCEKSize() / 8);
        $iv = random_bytes($algorithm->getIVSize() / 8);
        $tag = null;

        $ciphertext = $algorithm->encryptContent('Live long and Prosper.', $cek, $iv, null, $header, $tag);

        static::assertIsString($tag);
        static::assertSame($tagLength, mb_strlen($tag, '8bit'));
        static::assertSame(
            'Live long and Prosper.',
            $algorithm->decryptContent($ciphertext, $cek, $iv, null, $header, $tag)
        );
    }

    #[DataProvider('dataAlgorithms')]
    #[Test]
    public function tagOfAnotherLengthIsRejected(AESCCM $algorithm, int $tagLength): void
    {
        $header = $this->header($algorithm);
        $cek = random_bytes($algorithm->getCEKSize() / 8);
        $iv = random_bytes($algorithm->getIVSize() / 8);
        $mode = sprintf('aes-%d-ccm', $algorithm->getCEKSize());
        $tag = '';
        $ciphertext = openssl_encrypt('Live long and Prosper.', $mode, $cek, OPENSSL_RAW_DATA, $iv, $tag, $header, 4);
        static::assertIsString($ciphertext);
        static::assertIsString($tag);
        static::assertNotSame($tagLength, mb_strlen($tag, '8bit'));

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Unable to decrypt the content');

        $algorithm->decryptContent($ciphertext, $cek, $iv, null, $header, $tag);
    }

    public static function dataAlgorithms(): iterable
    {
        yield 'A128CCM-16-64' => [new A128CCM_16_64(), 8];
        yield 'A128CCM-64-64' => [new A128CCM_64_64(), 8];
        yield 'A128CCM-16-128' => [new A128CCM_16_128(), 16];
        yield 'A128CCM-64-128' => [new A128CCM_64_128(), 16];
        yield 'A256CCM-16-64' => [new A256CCM_16_64(), 8];
        yield 'A256CCM-64-64' => [new A256CCM_64_64(), 8];
        yield 'A256CCM-16-128' => [new A256CCM_16_128(), 16];
        yield 'A256CCM-64-128' => [new A256CCM_64_128(), 16];
    }

    private function header(AESCCM $algorithm): string
    {
        return Base64UrlSafe::encodeUnpadded(sprintf('{"alg":"dir","enc":"%s"}', $algorithm->name()));
    }
}
