<?php

declare(strict_types=1);

namespace Jose\Component\Encryption\Algorithm\ContentEncryption;

final class A256CCM_64_64 extends AESCCM
{
    public function getCEKSize(): int
    {
        return 256;
    }

    public function name(): string
    {
        return 'A256CCM-16-64';
    }

    public function getIVSize(): int
    {
        return 7 * 8;
    }

    protected function getMode(): string
    {
        return 'aes-256-ccm';
    }

    protected function getTagLength(): int
    {
        return 8;
    }
}
