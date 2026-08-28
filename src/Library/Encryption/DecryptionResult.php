<?php

declare(strict_types=1);

namespace Jose\Component\Encryption;

use Jose\Component\Core\JWK;

/**
 * The result of the decryption of one recipient of a JWE.
 *
 * It replaces the "JWE &$jwe" and "?JWK &$jwk" output parameters of JWEDecrypter::decryptUsingKeySet(): the
 * decrypted JWE and the key that decrypted it are carried by the result instead of being written into variables of
 * the caller.
 */
final readonly class DecryptionResult
{
    private function __construct(
        private bool $decrypted,
        private JWE $jwe,
        private int $recipientIndex,
        private ?JWK $key
    ) {
    }

    /**
     * The recipient has been decrypted. The key is null when the JWE was already decrypted and nothing had to be
     * done.
     */
    public static function success(JWE $jwe, int $recipientIndex, ?JWK $key): self
    {
        return new self(true, $jwe, $recipientIndex, $key);
    }

    /**
     * No key of the key set was able to decrypt the recipient. The JWE is returned unchanged.
     */
    public static function failure(JWE $jwe, int $recipientIndex): self
    {
        return new self(false, $jwe, $recipientIndex, null);
    }

    /**
     * Returns true if the recipient has been decrypted, otherwise false.
     */
    public function isDecrypted(): bool
    {
        return $this->decrypted;
    }

    /**
     * The decrypted JWE, or the JWE given to the decrypter when the decryption failed. JWE objects are immutable:
     * this is not the object that has been given to the decrypter, but a copy of it with the payload set.
     */
    public function getJwe(): JWE
    {
        return $this->jwe;
    }

    /**
     * The index of the recipient that has been decrypted, as given to the decrypter.
     */
    public function getRecipientIndex(): int
    {
        return $this->recipientIndex;
    }

    /**
     * The key that decrypted the recipient, or null when the decryption failed or when the JWE was already
     * decrypted.
     */
    public function getKey(): ?JWK
    {
        return $this->key;
    }
}
