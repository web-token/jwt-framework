<?php

declare(strict_types=1);

namespace Jose\Experimental\Signature;

use Jose\Component\Signature\Algorithm\ECDSA;

final class ES256K extends ECDSA
{
    public function name(): string
    {
        return 'ES256K';
    }

    protected function getHashAlgorithm(): string
    {
        return 'sha256';
    }

    protected function getSignaturePartLength(): int
    {
        return 64;
    }
}
