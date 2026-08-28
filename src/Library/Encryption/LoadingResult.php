<?php

declare(strict_types=1);

namespace Jose\Component\Encryption;

use Jose\Component\Core\JWK;

/**
 * The result of the loading and the decryption of a token by the JWELoader.
 *
 * It replaces the "?int &$recipient" output parameter of JWELoader::loadAndDecryptWithKeySet(): the index of the
 * decrypted recipient is carried by the result instead of being written into a variable of the caller.
 */
final readonly class LoadingResult
{
    public function __construct(
        private JWE $jwe,
        private int $recipientIndex,
        private ?JWK $key
    ) {
    }

    /**
     * The loaded and decrypted JWE.
     */
    public function getJwe(): JWE
    {
        return $this->jwe;
    }

    /**
     * The index of the recipient that has been decrypted.
     */
    public function getRecipientIndex(): int
    {
        return $this->recipientIndex;
    }

    /**
     * The key that decrypted the recipient. It is null when the decrypter reported a JWE that was already
     * decrypted and hence used no key at all.
     */
    public function getKey(): ?JWK
    {
        return $this->key;
    }
}
