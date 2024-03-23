<?php

declare(strict_types=1);

namespace Jose\Experimental\Signature;

use Jose\Component\Signature\Algorithm\ECDSA;
use Override;

final readonly class ES256K extends ECDSA
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
