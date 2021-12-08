<?php

declare(strict_types=1);

namespace Jose\Component\Signature\Algorithm;

final class ES384 extends ECDSA
{
    public function name(): string
    {
        return 'ES384';
    }

    protected function getHashAlgorithm(): string
    {
        return 'sha384';
    }

    protected function getSignaturePartLength(): int
    {
        return 96;
    }
}
