<?php

declare(strict_types=1);

namespace Jose\Component\Signature\Algorithm;

use Override;

/**
 * The "ES256K" algorithm of RFC 8812 section 3: ECDSA over the secp256k1 curve with SHA-256.
 *
 * The algorithm lived in the experimental package until 4.3, although RFC 8812 has registered it since 2020. The
 * class is not final because the deprecated Jose\Experimental\Signature\ES256K extends it until 5.0.0.
 */
readonly class ES256K extends ECDSA
{
    #[Override]
    public function name(): string
    {
        return 'ES256K';
    }

    #[Override]
    protected function getHashAlgorithm(): string
    {
        return 'sha256';
    }

    #[Override]
    protected function getSignaturePartLength(): int
    {
        return 64;
    }
}
