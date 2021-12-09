<?php

declare(strict_types=1);

namespace Jose\Component\Encryption\Algorithm\ContentEncryption;

final class A256CBCHS512 extends AESCBCHS
{
    public function getCEKSize(): int
    {
        return 512;
    }

    public function name(): string
    {
        return 'A256CBC-HS512';
    }

    protected function getHashAlgorithm(): string
    {
        return 'sha512';
    }

    protected function getMode(): string
    {
        return 'aes-256-cbc';
    }
}
