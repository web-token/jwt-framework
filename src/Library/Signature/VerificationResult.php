<?php

declare(strict_types=1);

namespace Jose\Component\Signature;

use Jose\Component\Core\JWK;

/**
 * The result of the verification of one signature of a JWS.
 *
 * It replaces the "?JWK &$jwk" output parameter of JWSVerifier::verifyWithKeySet(): the key that verified the
 * signature is carried by the result instead of being written into a variable of the caller.
 */
final readonly class VerificationResult
{
    private function __construct(
        private bool $verified,
        private int $signatureIndex,
        private ?JWK $key
    ) {
    }

    /**
     * The signature has been verified with the given key.
     */
    public static function success(int $signatureIndex, JWK $key): self
    {
        return new self(true, $signatureIndex, $key);
    }

    /**
     * No key of the key set was able to verify the signature.
     */
    public static function failure(int $signatureIndex): self
    {
        return new self(false, $signatureIndex, null);
    }

    /**
     * Returns true if the signature has been verified, otherwise false.
     */
    public function isVerified(): bool
    {
        return $this->verified;
    }

    /**
     * The index of the signature that has been verified, as given to the verifier.
     */
    public function getSignatureIndex(): int
    {
        return $this->signatureIndex;
    }

    /**
     * The key that verified the signature, or null when the verification failed.
     */
    public function getKey(): ?JWK
    {
        return $this->key;
    }
}
