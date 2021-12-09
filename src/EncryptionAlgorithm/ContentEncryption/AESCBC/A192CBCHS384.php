<?php

declare(strict_types=1);

namespace Jose\Component\Encryption\Algorithm\ContentEncryption;

final class A192CBCHS384 extends AESCBCHS
{
    public function getCEKSize(): int
    {
        return 384;
    }

    public function name(): string
    {
        return 'A192CBC-HS384';
    }

    protected function getHashAlgorithm(): string
    {
        return 'sha384';
    }

    protected function getMode(): string
    {
        return 'aes-192-cbc';
    }
}
