<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Encryption;

use Jose\Component\Core\Exception\InvalidKeyException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Core\Util\JsonConverter;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Throwable;

/**
 * The "key_ops" parameter of a key is read according to what the key does. With "dir", the key encrypts and decrypts
 * the content, so "key_ops" must contain "encrypt" or "decrypt". With a key agreement algorithm, it derives a key, and
 * "deriveKey" and "deriveBits" are both accepted.
 *
 * @internal
 */
final class KeyOperationsTest extends EncryptionTestCase
{
    private const PAYLOAD = 'Live long and Prosper.';

    private const DIRECT_ENCRYPTION_REFUSAL = 'Key cannot be used to encrypt the content: its "key_ops" parameter does not contain "encrypt".';

    private const DIRECT_DECRYPTION_ERROR = InvalidKeyException::class . ': Key cannot be used to decrypt the content: its "key_ops" parameter does not contain "decrypt".';

    /**
     * @param list<string> $operations
     */
    #[DataProvider('directKeyOperationsWithoutEncrypt')]
    #[Test]
    public function aDirectKeyThatDoesNotAllowEncryptIsRefused(array $operations): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage(self::DIRECT_ENCRYPTION_REFUSAL);

        $this->build('dir', 'A128GCM', $this->getDirectKey($operations));
    }

    /**
     * @param list<string> $operations
     */
    #[DataProvider('directKeyOperationsWithoutDecrypt')]
    #[Test]
    public function aDirectKeyThatDoesNotAllowDecryptIsRefused(array $operations): void
    {
        $token = $this->build('dir', 'A128GCM', $this->getDirectKey(['encrypt']));
        $key = $this->getDirectKey($operations);

        static::assertNull($this->decrypt($token, ['dir', 'A128GCM'], $key, errors: $errors));
        static::assertSame([self::DIRECT_DECRYPTION_ERROR], $errors);
    }

    /**
     * @param list<string>|null $operations
     */
    #[DataProvider('directKeyOperationsThatAllowTheContentOperations')]
    #[Test]
    public function aDirectKeyThatAllowsTheContentOperationsIsAccepted(?array $operations): void
    {
        $key = $this->getDirectKey($operations);

        static::assertSame(
            self::PAYLOAD,
            $this->decrypt($this->build('dir', 'A128GCM', $key), ['dir', 'A128GCM'], $key)
        );
    }

    /**
     * A key set may hold keys meant for other algorithms: a key that does not allow "decrypt" is skipped, even when it
     * would open the token, and the next key is tried.
     */
    #[Test]
    public function aDirectKeyThatDoesNotAllowDecryptIsSkipped(): void
    {
        $token = $this->build('dir', 'A128GCM', $this->getDirectKey(['encrypt']));
        $keys = new JWKSet([
            $this->getDirectKey(['wrapKey', 'unwrapKey']),
            $this->getDirectKey(['encrypt', 'decrypt']),
        ]);

        static::assertSame(self::PAYLOAD, $this->decrypt($token, ['dir', 'A128GCM'], $keys, errors: $errors));
        static::assertSame([self::DIRECT_DECRYPTION_ERROR], $errors);
    }

    /**
     * Such a key is refused by the check that applies to every mode, with the same message as before.
     *
     * @param list<string> $operations
     */
    #[DataProvider('keyOperationsWithoutEncryptionOperation')]
    #[Test]
    public function aDirectKeyWithoutAnyEncryptionOperationIsStillRefused(array $operations): void
    {
        $token = $this->build('dir', 'A128GCM', $this->getDirectKey(null));
        $key = $this->getDirectKey($operations);

        static::assertNull($this->decrypt($token, ['dir', 'A128GCM'], $key, errors: $errors));
        static::assertSame([InvalidKeyException::class . ': Key cannot be used to decrypt'], $errors);

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/^Key cannot be used to encrypt$/');

        $this->build('dir', 'A128GCM', $key);
    }

    /**
     * The encrypted key of an A128GCMKW token is an AES-GCM ciphertext computed with an empty AAD, like the content of
     * a JSON "dir" token that has neither a protected header nor an "aad" member. A key restricted to key wrapping
     * would open it as content and return the CEK of the token: it is refused.
     */
    #[Test]
    public function aKeyWrappingKeyCannotDecryptDirectContent(): void
    {
        $keyWrappingKey = new JWK([
            'kty' => 'oct',
            'k' => Base64UrlSafe::encodeUnpadded(random_bytes(16)),
            'key_ops' => ['wrapKey', 'unwrapKey'],
        ]);
        $wrapped = $this->getJWESerializerManager()
            ->unserialize($this->build('A128GCMKW', 'A128GCM', $keyWrappingKey));
        $forged = JsonConverter::encode([
            'header' => [
                'alg' => 'dir',
                'enc' => 'A128GCM',
            ],
            'iv' => $wrapped->getSharedProtectedHeaderParameter('iv'),
            'ciphertext' => Base64UrlSafe::encodeUnpadded((string) $wrapped->getRecipient(0)->getEncryptedKey()),
            'tag' => $wrapped->getSharedProtectedHeaderParameter('tag'),
        ]);

        static::assertNull($this->decrypt($forged, ['dir', 'A128GCMKW', 'A128GCM'], $keyWrappingKey, errors: $errors));
        static::assertSame([self::DIRECT_DECRYPTION_ERROR], $errors);
    }

    /**
     * @param list<string> $operations
     */
    #[DataProvider('ephemeralKeyAgreements')]
    #[Test]
    public function anEphemeralKeyAgreementAcceptsDeriveKeyAndDeriveBitsOnBothSides(string $alg, array $operations): void
    {
        $recipientKey = self::withOperations($this->getRecipientKey(), $operations);
        $token = $this->build($alg, 'A128GCM', $recipientKey->toPublic());

        static::assertSame(self::PAYLOAD, $this->decrypt($token, [$alg, 'A128GCM'], $recipientKey));
    }

    /**
     * The builder checks the key of the recipient and the key of the sender.
     *
     * @param list<string> $operations
     */
    #[DataProvider('staticKeyAgreements')]
    #[Test]
    public function aStaticKeyAgreementAcceptsDeriveKeyAndDeriveBitsForBothKeys(string $alg, array $operations): void
    {
        $recipientKey = self::withOperations($this->getRecipientKey(), $operations);
        $senderKey = self::withOperations($this->getSenderKey(), $operations);

        static::assertNotEmpty($this->build($alg, 'A128GCM', $recipientKey->toPublic(), $senderKey));
    }

    /**
     * @param list<string> $operations
     */
    #[DataProvider('keyOperationsWithoutEncryptionOperation')]
    #[Test]
    public function aKeyAgreementKeyWithoutAnyEncryptionOperationIsStillRefused(array $operations): void
    {
        $recipientKey = self::withOperations($this->getRecipientKey(), $operations);
        $token = $this->build('ECDH-ES', 'A128GCM', $this->getRecipientKey()->toPublic());

        static::assertNull($this->decrypt($token, ['ECDH-ES', 'A128GCM'], $recipientKey));

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('Key cannot be used to encrypt');

        $this->build('ECDH-ES', 'A128GCM', $recipientKey->toPublic());
    }

    /**
     * Only key agreement algorithms derive a key: a key wrapping key restricted to "deriveBits" cannot encrypt, and one
     * restricted to "deriveKey" cannot decrypt.
     */
    #[DataProvider('keyWrappingAlgorithms')]
    #[Test]
    public function aKeyWrappingKeyDoesNotAcceptTheOtherDerivationOperation(string $alg): void
    {
        $k = Base64UrlSafe::encodeUnpadded(random_bytes(16));
        $token = $this->build($alg, 'A128GCM', new JWK([
            'kty' => 'oct',
            'k' => $k,
        ]));

        static::assertNull($this->decrypt($token, [$alg, 'A128GCM'], new JWK([
            'kty' => 'oct',
            'k' => $k,
            'key_ops' => ['deriveKey'],
        ])));

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('Key cannot be used to encrypt');

        $this->build($alg, 'A128GCM', new JWK([
            'kty' => 'oct',
            'k' => $k,
            'key_ops' => ['deriveBits'],
        ]));
    }

    /**
     * AES-GCM keys exported by WebCrypto carry "encrypt" and "decrypt" whatever the algorithm they are used with.
     */
    #[Test]
    public function aKeyWrappingKeyWithTheContentOperationsIsStillAccepted(): void
    {
        $key = new JWK([
            'kty' => 'oct',
            'k' => Base64UrlSafe::encodeUnpadded(random_bytes(16)),
            'key_ops' => ['encrypt', 'decrypt'],
        ]);

        static::assertSame(
            self::PAYLOAD,
            $this->decrypt($this->build('A128GCMKW', 'A128GCM', $key), ['A128GCMKW', 'A128GCM'], $key)
        );
    }

    /**
     * @return iterable<string, array{list<string>}>
     */
    public static function directKeyOperationsWithoutEncrypt(): iterable
    {
        yield 'wrapKey' => [['wrapKey']];
        yield 'deriveKey' => [['deriveKey']];
        yield 'wrapKey and unwrapKey' => [['wrapKey', 'unwrapKey']];
        yield 'deriveKey and deriveBits' => [['deriveKey', 'deriveBits']];
        yield 'decrypt and wrapKey' => [['decrypt', 'wrapKey']];
    }

    /**
     * @return iterable<string, array{list<string>}>
     */
    public static function directKeyOperationsWithoutDecrypt(): iterable
    {
        yield 'unwrapKey' => [['unwrapKey']];
        yield 'deriveBits' => [['deriveBits']];
        yield 'wrapKey and unwrapKey' => [['wrapKey', 'unwrapKey']];
        yield 'deriveKey and deriveBits' => [['deriveKey', 'deriveBits']];
        yield 'encrypt and unwrapKey' => [['encrypt', 'unwrapKey']];
    }

    /**
     * @return iterable<string, array{list<string>|null}>
     */
    public static function directKeyOperationsThatAllowTheContentOperations(): iterable
    {
        yield 'no "key_ops" parameter' => [null];
        yield 'encrypt and decrypt' => [['encrypt', 'decrypt']];
        yield 'all the encryption operations' => [
            ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey', 'deriveKey', 'deriveBits'],
        ];
    }

    /**
     * @return iterable<string, array{list<string>}>
     */
    public static function keyOperationsWithoutEncryptionOperation(): iterable
    {
        yield 'no operation' => [[]];
        yield 'sign and verify' => [['sign', 'verify']];
    }

    /**
     * @return iterable<string, array{string, list<string>}>
     */
    public static function ephemeralKeyAgreements(): iterable
    {
        foreach (['ECDH-ES', 'ECDH-ES+A128KW'] as $alg) {
            yield $alg . ', deriveKey' => [$alg, ['deriveKey']];
            yield $alg . ', deriveBits' => [$alg, ['deriveBits']];
        }
    }

    /**
     * @return iterable<string, array{string, list<string>}>
     */
    public static function staticKeyAgreements(): iterable
    {
        foreach (['ECDH-SS', 'ECDH-SS+A128KW'] as $alg) {
            yield $alg . ', deriveKey' => [$alg, ['deriveKey']];
            yield $alg . ', deriveBits' => [$alg, ['deriveBits']];
        }
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function keyWrappingAlgorithms(): iterable
    {
        yield 'A128KW' => ['A128KW'];
        yield 'A128GCMKW' => ['A128GCMKW'];
    }

    /**
     * @param list<string>|null $operations
     */
    private static function withOperations(JWK $key, ?array $operations): JWK
    {
        if ($operations === null) {
            return $key;
        }

        return new JWK([
            ...$key->all(),
            'key_ops' => $operations,
        ]);
    }

    /**
     * @param list<string>|null $operations
     */
    private function getDirectKey(?array $operations): JWK
    {
        return self::withOperations(new JWK([
            'kty' => 'oct',
            'k' => Base64UrlSafe::encodeUnpadded(hex2bin('00112233445566778899AABBCCDDEEFF')),
        ]), $operations);
    }

    private function getRecipientKey(): JWK
    {
        return new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ',
            'y' => 'e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck',
            'd' => 'VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw',
        ]);
    }

    private function getSenderKey(): JWK
    {
        return new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'OSo9FXcQCqDR6G3INwuMZn9_StSV6eLKn1KQIWufuyA',
            'y' => 'c4v6g44omMI_949wkYtJSG_pOyhyqqqJ7zqqdv5vwGU',
            'd' => 'xBRebaWQIa9DAxChfcOGDnfM39RMILisUxW16XHVN7c',
        ]);
    }

    private function build(string $alg, string $enc, JWK $recipientKey, ?JWK $senderKey = null): string
    {
        $builder = $this->getJWEBuilderFactory()
            ->create([$alg, $enc])
            ->withPayload(self::PAYLOAD)
            ->withSharedProtectedHeader([
                'alg' => $alg,
                'enc' => $enc,
            ])
            ->addRecipient($recipientKey);
        if ($senderKey !== null) {
            $builder = $builder->withSenderKey($senderKey);
        }

        return $this->getJWESerializerManager()
            ->serialize('jwe_compact', $builder->build(), 0);
    }

    /**
     * @param list<string> $algorithms
     * @param list<string>|null $errors Receives what the decrypter met while trying the keys, as "class: message"
     */
    private function decrypt(
        string $token,
        array $algorithms,
        JWK|JWKSet $keys,
        ?JWK $senderKey = null,
        ?array &$errors = null
    ): ?string {
        $errors = [];
        $result = $this->getJWEDecrypterFactory()
            ->create($algorithms)
            ->decrypt(
                $this->getJWESerializerManager()->unserialize($token),
                $keys,
                0,
                $senderKey,
                static function (Throwable $throwable) use (&$errors): void {
                    $errors[] = $throwable::class . ': ' . $throwable->getMessage();
                }
            );

        return $result->isDecrypted() ? $result->getJwe()
            ->getPayload() : null;
    }
}
