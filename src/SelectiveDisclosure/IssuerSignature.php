<?php

declare(strict_types=1);

namespace Jose\SelectiveDisclosure;

use Jose\Component\Core\JWK;

/**
 * One of the signatures of an Issuer-signed JWT in the JWS JSON serialization: the key of the Issuer, the protected
 * header and the unprotected header of the signature, as JWSBuilderInterface::addSignature() takes them.
 *
 * The protected header names a signature algorithm in "alg". The unprotected header may carry parameters such as
 * "kid", but not "disclosures" nor "kb_jwt", which carry the Disclosures and the Key Binding JWT of the SD-JWT.
 *
 * @see SDJWTIssuerInterface::issueJson()
 */
final readonly class IssuerSignature
{
    /**
     * @param array<string, mixed> $protectedHeader
     * @param array<string, mixed> $header the unprotected header
     */
    public function __construct(
        private JWK $key,
        private array $protectedHeader,
        private array $header = []
    ) {
    }

    public function getKey(): JWK
    {
        return $this->key;
    }

    /**
     * @return array<string, mixed>
     */
    public function getProtectedHeader(): array
    {
        return $this->protectedHeader;
    }

    /**
     * The unprotected header.
     *
     * @return array<string, mixed>
     */
    public function getHeader(): array
    {
        return $this->header;
    }
}
