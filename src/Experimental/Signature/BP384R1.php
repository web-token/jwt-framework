<?php

declare(strict_types=1);

namespace Jose\Experimental\Signature;

use Jose\Component\Signature\Algorithm\ECDSA;
use Override;

/**
 * ECDSA using the brainpoolP384r1 curve ("BP-384") and SHA-384.
 *
 * Neither the algorithm nor the curve is registered with IANA. Both identifiers follow the de facto convention adopted
 * by the existing implementations.
 */
final readonly class BP384R1 extends ECDSA
{
    #[Override]
    public function name(): string
    {
        return 'BP384R1';
    }

    #[Override]
    protected function getHashAlgorithm(): string
    {
        return 'sha384';
    }

    #[Override]
    protected function getSignaturePartLength(): int
    {
        return 96;
    }
}
