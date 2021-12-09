<?php

declare(strict_types=1);

namespace Jose\Component\Signature\Algorithm;

final class ES512 extends ECDSA
{
    public function name(): string
    {
        return 'ES512';
    }

    protected function getHashAlgorithm(): string
    {
        return 'sha512';
    }

    protected function getSignaturePartLength(): int
    {
        return 132;
    }
}
