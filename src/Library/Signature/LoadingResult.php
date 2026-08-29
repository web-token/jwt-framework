<?php

declare(strict_types=1);

namespace Jose\Component\Signature;

use Jose\Component\Core\JWK;

/**
 * The result of the loading and the verification of a token by the JWSLoader.
 *
 * It replaces the "?int &$signature" output parameter of JWSLoader::loadAndVerifyWithKeySet(): the index of the
 * verified signature is carried by the result instead of being written into a variable of the caller.
 */
final readonly class LoadingResult
{
    public function __construct(
        private JWS $jws,
        private int $signatureIndex,
        private JWK $key
    ) {
    }

    /**
     * The loaded JWS.
     */
    public function getJws(): JWS
    {
        return $this->jws;
    }

    /**
     * The index of the signature that has been verified.
     */
    public function getSignatureIndex(): int
    {
        return $this->signatureIndex;
    }

    /**
     * The key that verified the signature.
     */
    public function getKey(): JWK
    {
        return $this->key;
    }
}
