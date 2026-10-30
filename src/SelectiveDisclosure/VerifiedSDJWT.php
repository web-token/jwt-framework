<?php

declare(strict_types=1);

namespace Jose\SelectiveDisclosure;

use Jose\Component\Core\JWK;
use Jose\Component\Signature\JWS;

/**
 * The result of the verification of an SD-JWT, or of an SD-JWT+KB, by the Verifier.
 *
 * It carries the Processed SD-JWT Payload of RFC 9901 section 7.1, that is the claims of the Issuer-signed JWT with
 * the disclosed claims inserted and the digests removed, along with the verified tokens and the keys that verified
 * them.
 */
final readonly class VerifiedSDJWT
{
    /**
     * @param array<string, mixed> $claims
     */
    public function __construct(
        private SDJWT $sdJwt,
        private array $claims,
        private JWS $issuerSignedJwt,
        private JWK $issuerKey,
        private ?JWS $keyBindingJwt = null,
        private ?JWK $holderKey = null
    ) {
    }

    /**
     * The verified SD-JWT, as it was presented.
     */
    public function getSdJwt(): SDJWT
    {
        return $this->sdJwt;
    }

    /**
     * The Processed SD-JWT Payload: the claims of the Issuer-signed JWT and the claims disclosed by the presented
     * Disclosures, without "_sd", "_sd_alg" and the digests of the claims that are not disclosed.
     *
     * @return array<string, mixed>
     */
    public function getClaims(): array
    {
        return $this->claims;
    }

    /**
     * The Issuer-signed JWT, as loaded and verified.
     */
    public function getIssuerSignedJwt(): JWS
    {
        return $this->issuerSignedJwt;
    }

    /**
     * The key of the Issuer that verified the Issuer-signed JWT.
     */
    public function getIssuerKey(): JWK
    {
        return $this->issuerKey;
    }

    public function hasKeyBinding(): bool
    {
        return $this->keyBindingJwt !== null;
    }

    /**
     * The Key Binding JWT, as loaded and verified, or null when Key Binding was not verified.
     */
    public function getKeyBindingJwt(): ?JWS
    {
        return $this->keyBindingJwt;
    }

    /**
     * The key of the "cnf" claim that verified the Key Binding JWT, or null when Key Binding was not verified.
     */
    public function getHolderKey(): ?JWK
    {
        return $this->holderKey;
    }
}
