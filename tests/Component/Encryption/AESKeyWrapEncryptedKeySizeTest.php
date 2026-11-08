<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Encryption;

use ArrayObject;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\Exception\InvalidArgumentException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Core\Util\ECKey;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A128GCM;
use Jose\Component\Encryption\Algorithm\KeyEncryption\PBES2AESKW;
use Jose\Component\Encryption\JWE;
use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\Encryption\Serializer\CompactSerializer;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Throwable;
use function array_fill_keys;
use function array_keys;
use function array_map;
use function memory_get_peak_usage;
use function memory_reset_peak_usage;
use function strlen;
use function substr;

/**
 * The EC keys are the ones of RFC 7518 appendix C: Bob is the recipient, and the ephemeral key of Alice is used as the
 * static key of the sender for ECDH-SS.
 *
 * @internal
 */
final class AESKeyWrapEncryptedKeySizeTest extends EncryptionTestCase
{
    private const PAYLOAD = 'Live long and prosper.';

    private const INVALID_SIZE = InvalidArgumentException::class . ': Invalid encrypted key size';

    private const CONTENT_ENCRYPTION_ALGORITHMS = [
        'A128GCM',
        'A192GCM',
        'A256GCM',
        'A128CBC-HS256',
        'A192CBC-HS384',
        'A256CBC-HS512',
    ];

    private const RECIPIENT_KEY = [
        'kty' => 'EC',
        'crv' => 'P-256',
        'x' => 'weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ',
        'y' => 'e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck',
        'd' => 'VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw',
    ];

    private const SENDER_KEY = [
        'kty' => 'EC',
        'crv' => 'P-256',
        'x' => 'gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0',
        'y' => 'SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps',
        'd' => '0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo',
    ];

    /**
     * The last token carries a key that unwraps, but not to the size expected by its "enc" parameter. The other
     * content encryption algorithm uses the same IV size, so that the token reaches the key management step.
     */
    #[DataProvider('dataAlgorithms')]
    #[Test]
    public function anEncryptedKeyOfAnotherSizeIsRejectedBeforeBeingUnwrapped(string $alg, string $enc): void
    {
        $token = $this->issue($alg, $enc);
        $encryptedKey = self::encryptedKeyOf($token);
        $otherEnc = match ($enc) {
            'A256GCM' => 'A128GCM',
            'A128GCM', 'A192GCM' => 'A256GCM',
            'A256CBC-HS512' => 'A128CBC-HS256',
            default => 'A256CBC-HS512',
        };

        static::assertSame([], $this->failures($alg, $token));

        $tokens = [
            'one block longer' => self::rewrite($token, encryptedKey: $encryptedKey . random_bytes(8)),
            'one block shorter' => self::rewrite($token, encryptedKey: substr($encryptedKey, 8)),
            'one byte longer' => self::rewrite($token, encryptedKey: $encryptedKey . "\0"),
            'empty' => self::rewrite($token, encryptedKey: ''),
            'wrapped for another content encryption algorithm' => self::rewrite(
                $this->issue($alg, $otherEnc),
                enc: $enc
            ),
        ];
        $failures = [];
        foreach ($tokens as $name => $invalidToken) {
            $failures[$name] = $this->failures($alg, $invalidToken);
        }

        static::assertSame(array_fill_keys(array_keys($tokens), [self::INVALID_SIZE]), $failures);
    }

    #[DataProvider('dataAlgorithms')]
    #[Test]
    public function anOversizedEncryptedKeyIsRejectedWithoutBeingProcessed(string $alg, string $enc): void
    {
        $encryptedKey = random_bytes(1 << 20);
        $jwe = self::unserialize(self::rewrite($this->issue($alg, $enc), encryptedKey: $encryptedKey));
        [$key, $senderKey] = self::decryptionKeys($alg);
        $decrypter = $this->getJWEDecrypterFactory()
            ->create([$alg, $enc]);

        memory_reset_peak_usage();
        $usage = memory_get_peak_usage();
        $result = $decrypter->decrypt($jwe, $key, 0, $senderKey);
        $allocated = memory_get_peak_usage() - $usage;

        static::assertFalse($result->isDecrypted());
        static::assertLessThan(strlen($encryptedKey), $allocated);
    }

    #[Test]
    public function theKeyIsNotDerivedFromThePasswordForAnEncryptedKeyOfAnotherSize(): void
    {
        $token = $this->issue('PBES2-HS256+A128KW', 'A128GCM');
        $invalidToken = self::rewrite($token, encryptedKey: self::encryptedKeyOf($token) . random_bytes(8));
        [$password] = self::decryptionKeys('PBES2-HS256+A128KW');
        $calls = new ArrayObject();
        $decrypter = new JWEDecrypter(new AlgorithmManager([
            new CountingPBES2HS256A128KW($calls, PBES2AESKW::DEFAULT_MAX_COUNT),
            new A128GCM(),
        ]));

        static::assertTrue($decrypter->decrypt(self::unserialize($token), $password, 0)->isDecrypted());
        static::assertCount(1, $calls);
        static::assertFalse($decrypter->decrypt(self::unserialize($invalidToken), $password, 0)->isDecrypted());
        static::assertCount(1, $calls);
    }

    /**
     * The private key of the recipient is on another curve than the token, so that the key agreement would fail.
     */
    #[DataProvider('dataKeyAgreementAlgorithms')]
    #[Test]
    public function theKeyIsNotAgreedForAnEncryptedKeyOfAnotherSize(string $alg): void
    {
        $token = $this->issue($alg, 'A128GCM');
        $invalidToken = self::rewrite($token, encryptedKey: self::encryptedKeyOf($token) . random_bytes(8));
        [, $senderKey] = self::decryptionKeys($alg);

        static::assertSame(
            [self::INVALID_SIZE],
            $this->failures($alg, $invalidToken, ECKey::createECKey('P-384'), $senderKey)
        );
    }

    public static function dataAlgorithms(): iterable
    {
        yield 'A128KW' => ['A128KW', 'A128GCM'];
        yield 'A192KW' => ['A192KW', 'A192CBC-HS384'];
        yield 'A256KW' => ['A256KW', 'A256CBC-HS512'];
        yield 'PBES2-HS256+A128KW' => ['PBES2-HS256+A128KW', 'A128CBC-HS256'];
        yield 'PBES2-HS512+A256KW' => ['PBES2-HS512+A256KW', 'A256GCM'];
        yield 'ECDH-ES+A128KW' => ['ECDH-ES+A128KW', 'A128GCM'];
        yield 'ECDH-ES+A256KW' => ['ECDH-ES+A256KW', 'A256CBC-HS512'];
        yield 'ECDH-SS+A128KW' => ['ECDH-SS+A128KW', 'A192GCM'];
        yield 'ECDH-SS+A256KW' => ['ECDH-SS+A256KW', 'A256GCM'];
    }

    public static function dataKeyAgreementAlgorithms(): iterable
    {
        yield 'ECDH-ES+A128KW' => ['ECDH-ES+A128KW'];
        yield 'ECDH-SS+A128KW' => ['ECDH-SS+A128KW'];
    }

    private function issue(string $alg, string $enc): string
    {
        $builder = $this->getJWEBuilderFactory()
            ->create([$alg, $enc])
            ->create()
            ->withPayload(self::PAYLOAD)
            ->withSharedProtectedHeader([
                'alg' => $alg,
                'enc' => $enc,
            ]);
        if (str_starts_with($alg, 'ECDH-SS')) {
            $builder = $builder->withSenderKey(new JWK(self::SENDER_KEY));
        }
        $recipientKey = match (true) {
            str_starts_with($alg, 'ECDH') => (new JWK(self::RECIPIENT_KEY))->toPublic(),
            default => self::sharedKey($alg),
        };

        return (new CompactSerializer())->serialize($builder->addRecipient($recipientKey)->build(), 0);
    }

    /**
     * The failures met by the decrypter, as the class and the message of each exception.
     *
     * @return list<string>
     */
    private function failures(string $alg, string $token, ?JWK $key = null, ?JWK $senderKey = null): array
    {
        if ($key === null) {
            [$key, $senderKey] = self::decryptionKeys($alg);
        }
        $failures = [];
        $result = $this->getJWEDecrypterFactory()
            ->create([$alg, ...self::CONTENT_ENCRYPTION_ALGORITHMS])
            ->decrypt(
                self::unserialize($token),
                $key,
                0,
                $senderKey,
                static function (Throwable $failure) use (&$failures): void {
                    $failures[] = $failure;
                }
            );
        if ($result->isDecrypted()) {
            static::assertSame(self::PAYLOAD, $result->getJwe()->getPayload());
        }

        return array_map(
            static fn (Throwable $failure): string => $failure::class . ': ' . $failure->getMessage(),
            $failures
        );
    }

    /**
     * With ECDH-SS, the decrypter takes the private key of the recipient as the key and the public key of the sender
     * as the sender key.
     *
     * @return array{JWK, JWK|null}
     */
    private static function decryptionKeys(string $alg): array
    {
        return match (true) {
            str_starts_with($alg, 'ECDH-ES') => [new JWK(self::RECIPIENT_KEY), null],
            str_starts_with($alg, 'ECDH-SS') => [new JWK(self::RECIPIENT_KEY), (new JWK(self::SENDER_KEY))->toPublic()],
            default => [self::sharedKey($alg), null],
        };
    }

    private static function sharedKey(string $alg): JWK
    {
        $size = match ($alg) {
            'A128KW' => 16,
            'A192KW' => 24,
            default => 32,
        };

        return new JWK([
            'kty' => 'oct',
            'k' => Base64UrlSafe::encodeUnpadded(str_repeat("\x2a", $size)),
        ]);
    }

    private static function unserialize(string $token): JWE
    {
        return (new CompactSerializer())->unserialize($token);
    }

    private static function encryptedKeyOf(string $token): string
    {
        return self::unserialize($token)->getRecipient(0)->getEncryptedKey() ?? '';
    }

    /**
     * Replaces the encrypted key or the "enc" parameter of a token in the compact serialization. The protected header
     * is no longer the one covered by the authentication tag, which does not matter here: the tokens are rejected
     * before the content is decrypted.
     */
    private static function rewrite(string $token, ?string $encryptedKey = null, ?string $enc = null): string
    {
        $parts = explode('.', $token);
        if ($enc !== null) {
            $header = JsonConverter::decode(Base64UrlSafe::decodeNoPadding($parts[0]));
            $header['enc'] = $enc;
            $parts[0] = Base64UrlSafe::encodeUnpadded(JsonConverter::encode($header));
        }
        if ($encryptedKey !== null) {
            $parts[1] = Base64UrlSafe::encodeUnpadded($encryptedKey);
        }

        return implode('.', $parts);
    }
}
