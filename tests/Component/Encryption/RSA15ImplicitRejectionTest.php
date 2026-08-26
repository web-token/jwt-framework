<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Encryption;

use InvalidArgumentException;
use Jose\Component\Core\Util\RSAKey;
use Jose\Component\Encryption\Algorithm\KeyEncryption\RSA15;
use Jose\Component\Encryption\Algorithm\KeyEncryption\Util\RSACrypt;
use Jose\Component\KeyManagement\JWKFactory;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function mb_strlen;

/**
 * @internal
 */
final class RSA15ImplicitRejectionTest extends TestCase
{
    #[Test]
    public function validRoundTripStillWorks(): void
    {
        $jwk = JWKFactory::createRSAKey(2048, [
            'alg' => 'RSA1_5',
            'use' => 'enc',
        ]);
        $algorithm = new RSA15();
        $cek = random_bytes(16); // A128GCM CEK
        $header = [
            'alg' => 'RSA1_5',
            'enc' => 'A128GCM',
        ];

        $additionalHeader = [];
        $encrypted = $algorithm->encryptKey($jwk, $cek, $header, $additionalHeader);
        $decrypted = $algorithm->decryptKey($jwk, $encrypted, $header);

        static::assertSame($cek, $decrypted);
    }

    #[Test]
    public function malformedCiphertextDoesNotThrowAndReturnsExpectedLength(): void
    {
        $jwk = JWKFactory::createRSAKey(2048, [
            'alg' => 'RSA1_5',
            'use' => 'enc',
        ]);
        $algorithm = new RSA15();
        $key = RSAKey::createFromJWK($jwk);
        $garbage = "\x00" . random_bytes($key->getModulusLength() - 1);
        $header = [
            'alg' => 'RSA1_5',
            'enc' => 'A128GCM',
        ];

        $result = $algorithm->decryptKey($jwk, $garbage, $header);

        // 16 bytes for A128GCM, and (overwhelmingly) not a valid recovery.
        static::assertSame(16, mb_strlen($result, '8bit'));
    }

    #[Test]
    public function implicitRejectionRespectsEncCekLength(): void
    {
        $jwk = JWKFactory::createRSAKey(2048, [
            'alg' => 'RSA1_5',
            'use' => 'enc',
        ]);
        $algorithm = new RSA15();
        $key = RSAKey::createFromJWK($jwk);
        $garbage = "\x00" . random_bytes($key->getModulusLength() - 1);

        $lengths = [
            'A128GCM' => 16,
            'A192GCM' => 24,
            'A256GCM' => 32,
            'A128CBC-HS256' => 32,
            'A192CBC-HS384' => 48,
            'A256CBC-HS512' => 64,
        ];
        foreach ($lengths as $enc => $expected) {
            $result = $algorithm->decryptKey($jwk, $garbage, [
                'alg' => 'RSA1_5',
                'enc' => $enc,
            ]);
            static::assertSame($expected, mb_strlen($result, '8bit'), $enc);
        }
    }

    #[Test]
    public function legacyDirectDecryptStillThrowsOnGarbage(): void
    {
        $jwk = JWKFactory::createRSAKey(2048, [
            'alg' => 'RSA1_5',
            'use' => 'enc',
        ]);
        $key = RSAKey::createFromJWK($jwk);
        $garbage = "\x00" . random_bytes($key->getModulusLength() - 1);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Unable to decrypt');
        RSACrypt::decrypt($key, $garbage, RSACrypt::ENCRYPTION_PKCS1);
    }
}
