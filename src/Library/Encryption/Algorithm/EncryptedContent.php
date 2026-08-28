<?php

declare(strict_types=1);

namespace Jose\Component\Encryption\Algorithm;

/**
 * The ciphertext produced by a content encryption algorithm, together with the authentication tag when the
 * algorithm computes one.
 *
 * It is the return type announced for ContentEncryptionAlgorithm::encryptContent() in 5.0.0, where it replaces
 * the "?string &$tag" output parameter. It is not used by the interface yet: adding it now would break every
 * third-party implementation of the interface.
 */
final readonly class EncryptedContent
{
    public function __construct(
        private string $ciphertext,
        private ?string $tag = null
    ) {
    }

    /**
     * The encrypted content.
     */
    public function getCiphertext(): string
    {
        return $this->ciphertext;
    }

    /**
     * The authentication tag, or null when the algorithm does not compute one.
     */
    public function getTag(): ?string
    {
        return $this->tag;
    }
}
