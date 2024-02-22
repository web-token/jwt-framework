<?php

declare(strict_types=1);

namespace Jose\Component\Signature\Algorithm;

final class ES256 extends ECDSA
{
    public function name(): string
    {
        return 'ES256';
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
