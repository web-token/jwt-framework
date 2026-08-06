<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Encryption;

use Jose\Component\Core\JWK;
use Jose\Component\Encryption\Algorithm\KeyEncryption\KeyEncryption;
use Override;
use function func_num_args;

/**
 * A key encryption algorithm that declares the method signature as defined by the KeyEncryption interface in
 * 4.x: it does not expect the size of the CEK the JWEDecrypter passes as an additional argument.
 *
 * It performs no encryption at all: it is only used to check that such an implementation still works.
 */
final class LegacyKeyEncryptionAlgorithm implements KeyEncryption
{
    /**
     * Number of arguments received by the last call to the decryptKey method.
     */
    public int $receivedArgumentCount = 0;

    #[Override]
    public function name(): string
    {
        return 'legacy-key-encryption';
    }

    #[Override]
    public function allowedKeyTypes(): array
    {
        return ['oct'];
    }

    #[Override]
    public function getKeyManagementMode(): string
    {
        return self::MODE_ENCRYPT;
    }

    /**
     * @param array<string, mixed> $completeHeader
     * @param array<string, mixed> $additionalHeader
     */
    #[Override]
    public function encryptKey(JWK $key, string $cek, array $completeHeader, array &$additionalHeader): string
    {
        return $cek;
    }

    /**
     * @param array<string, mixed> $header
     */
    #[Override]
    public function decryptKey(JWK $key, string $encrypted_cek, array $header): string
    {
        $this->receivedArgumentCount = func_num_args();

        return $encrypted_cek;
    }
}
