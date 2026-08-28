<?php

declare(strict_types=1);

namespace Jose\Component\Signature;

use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\MacAlgorithm;
use Jose\Component\Signature\Algorithm\SignatureAlgorithm;
use function array_key_exists;

/**
 * A signature to compute, as declared by a call to JWSBuilder::addSignature().
 *
 * The specification is the immutable state of the builder: it holds what the caller provided and the
 * algorithm that was resolved from it, not the computed signature. The signature itself is produced by
 * JWSBuilder::build(), which is also where the specifications are checked against each other.
 *
 * @internal
 */
final readonly class SignatureSpec
{
    /**
     * @param array<string, mixed> $protectedHeader
     * @param array<string, mixed> $header
     */
    public function __construct(
        public JWK $key,
        public MacAlgorithm|SignatureAlgorithm $algorithm,
        public array $protectedHeader,
        public array $header
    ) {
    }

    /**
     * Indicates whether the payload has to be Base64Url encoded for this signature.
     *
     * The "b64" header parameter defined by RFC 7797 removes the encoding when it is set to false. It is
     * absent from the vast majority of the tokens, in which case the payload is encoded.
     */
    public function isPayloadEncoded(): bool
    {
        return ! array_key_exists('b64', $this->protectedHeader) || $this->protectedHeader['b64'] === true;
    }
}
