<?php

declare(strict_types=1);

namespace Jose\Component\Encryption\Algorithm\KeyEncryption;

/**
 * The output of an Integrated Encryption algorithm: the JWE Encrypted Key of the recipient and the JWE Ciphertext.
 * There is neither IV nor authentication tag in this key management mode: the ciphertext carries everything the
 * algorithm needs to authenticate it.
 */
final readonly class EncryptedPayload
{
    public function __construct(
        private string $encryptedKey,
        private string $ciphertext
    ) {
    }

    /**
     * The JWE Encrypted Key, the encapsulated key for HPKE.
     */
    public function getEncryptedKey(): string
    {
        return $this->encryptedKey;
    }

    /**
     * The JWE Ciphertext.
     */
    public function getCiphertext(): string
    {
        return $this->ciphertext;
    }
}
