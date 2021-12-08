<?php

declare(strict_types=1);

namespace Jose\Component\Encryption\Algorithm\ContentEncryption;

final class A128CCM_16_64 extends AESCCM
{
    public function getCEKSize(): int
    {
        return 128;
    }

    public function name(): string
    {
        return 'A128CCM-16-64';
    }

    public function getIVSize(): int
    {
        return 13 * 8;
    }

    protected function getMode(): string
    {
        return 'aes-128-ccm';
    }

    protected function getTagLength(): int
    {
        return 8;
    }
}
