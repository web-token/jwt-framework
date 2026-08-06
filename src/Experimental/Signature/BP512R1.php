<?php

declare(strict_types=1);

namespace Jose\Experimental\Signature;

use Jose\Component\Signature\Algorithm\ECDSA;
use Override;

/**
 * ECDSA using the brainpoolP512r1 curve ("BP-512") and SHA-512.
 *
 * Neither the algorithm nor the curve is registered with IANA. Both identifiers follow the de facto convention adopted
 * by the existing implementations.
 */
final readonly class BP512R1 extends ECDSA
{
    #[Override]
    public function name(): string
    {
        return 'BP512R1';
    }

    #[Override]
    protected function getHashAlgorithm(): string
    {
        return 'sha512';
    }

    #[Override]
    protected function getSignaturePartLength(): int
    {
        return 128;
    }
}
