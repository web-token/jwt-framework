<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Encryption;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\RSAKey;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A128GCM;
use Jose\Component\Encryption\Algorithm\KeyEncryption\RSA15;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\Encryption\Serializer\CompactSerializer;
use Jose\Component\KeyManagement\JWKFactory;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function mb_strlen;
use const E_USER_DEPRECATED;

/**
 * The expected CEK size is passed by the JWEDecrypter as an additional argument of the decryptKey method.
 * Until that argument is part of the KeyEncryption interface (5.0), RSA1_5 falls back to a hardcoded table
 * and triggers a deprecation.
 *
 * @internal
 */
final class RSA15ExpectedCekSizeTest extends TestCase
{
    #[Test]
    public function aDeprecationIsTriggeredWhenTheExpectedCekSizeIsNotProvided(): void
    {
        $jwk = $this->createKey();
        $algorithm = new RSA15();
        $cek = random_bytes(16); // A128GCM CEK
        $header = [
            'alg' => 'RSA1_5',
            'enc' => 'A128GCM',
        ];
        $additionalHeader = [];
        $encrypted = $algorithm->encryptKey($jwk, $cek, $header, $additionalHeader);

        $decrypted = null;
        $deprecations = $this->collectDeprecations(static function () use (
            $algorithm,
            $jwk,
            $encrypted,
            $header,
            &$decrypted
        ): void {
            $decrypted = $algorithm->decryptKey($jwk, $encrypted, $header);
        });

        static::assertSame($cek, $decrypted);
        static::assertCount(1, $deprecations);
        static::assertStringContainsString(
            'Calling "Jose\Component\Encryption\Algorithm\KeyEncryption\RSA15::decryptKey()" without the size of the key expected by the content encryption algorithm as fourth argument is deprecated.',
            $deprecations[0]
        );
    }

    #[Test]
    public function noDeprecationIsTriggeredWhenTheExpectedCekSizeIsProvided(): void
    {
        $jwk = $this->createKey();
        $algorithm = new RSA15();
        $cek = random_bytes(16); // A128GCM CEK
        $header = [
            'alg' => 'RSA1_5',
            'enc' => 'A128GCM',
        ];
        $additionalHeader = [];
        $encrypted = $algorithm->encryptKey($jwk, $cek, $header, $additionalHeader);

        $decrypted = null;
        $deprecations = $this->collectDeprecations(static function () use (
            $algorithm,
            $jwk,
            $encrypted,
            $header,
            &$decrypted
        ): void {
            $decrypted = $algorithm->decryptKey($jwk, $encrypted, $header, 128);
        });

        static::assertSame($cek, $decrypted);
        static::assertSame([], $deprecations);
    }

    #[Test]
    public function theProvidedCekSizeIsUsedForTheImplicitRejection(): void
    {
        $jwk = $this->createKey();
        $algorithm = new RSA15();
        $key = RSAKey::createFromJWK($jwk);
        $garbage = "\x00" . random_bytes($key->getModulusLength() - 1);
        // The content encryption algorithm is unknown to the hardcoded table.
        $header = [
            'alg' => 'RSA1_5',
            'enc' => 'FOO-256',
        ];

        $result = $algorithm->decryptKey($jwk, $garbage, $header, 256);

        static::assertSame(32, mb_strlen($result, '8bit'));
    }

    #[Test]
    public function theJweDecrypterProvidesTheExpectedCekSize(): void
    {
        $jwk = $this->createKey();
        $algorithmManager = new AlgorithmManager([new RSA15(), new A128GCM()]);
        $token = $this->createToken($algorithmManager, $jwk, 'RSA1_5');

        $jwe = (new CompactSerializer())->unserialize($token);
        $decrypter = new JWEDecrypter($algorithmManager);

        $deprecations = $this->collectDeprecations(static function () use ($decrypter, $jwe, $jwk): void {
            $jweToDecrypt = $jwe;
            static::assertTrue($decrypter->decryptUsingKey($jweToDecrypt, $jwk, 0));
            static::assertSame('Live long and prosper.', $jweToDecrypt->getPayload());
        });

        static::assertSame([], $deprecations);
    }

    #[Test]
    public function algorithmsThatDoNotExpectTheCekSizeStillWork(): void
    {
        $jwk = JWKFactory::createOctKey(256, [
            'use' => 'enc',
        ]);
        $algorithm = new LegacyKeyEncryptionAlgorithm();
        $algorithmManager = new AlgorithmManager([$algorithm, new A128GCM()]);
        $token = $this->createToken($algorithmManager, $jwk, $algorithm->name());

        $jwe = (new CompactSerializer())->unserialize($token);
        $decrypter = new JWEDecrypter($algorithmManager);

        static::assertTrue($decrypter->decryptUsingKey($jwe, $jwk, 0));
        static::assertSame('Live long and prosper.', $jwe->getPayload());
        static::assertSame(4, $algorithm->receivedArgumentCount);
    }

    private function createKey(): JWK
    {
        return JWKFactory::createRSAKey(2048, [
            'alg' => 'RSA1_5',
            'use' => 'enc',
        ]);
    }

    private function createToken(AlgorithmManager $algorithmManager, JWK $jwk, string $algorithm): string
    {
        $jwe = (new JWEBuilder($algorithmManager))
            ->withPayload('Live long and prosper.')
            ->withSharedProtectedHeader([
                'alg' => $algorithm,
                'enc' => 'A128GCM',
            ])
            ->addRecipient($jwk)
            ->build();

        return (new CompactSerializer())->serialize($jwe, 0);
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
}
