<?php

declare(strict_types=1);

namespace Jose\Experimental\ContentEncryption;

final class A128CCM_16_128 extends AESCCM
{
    public function getCEKSize(): int
    {
        return 128;
    }

    public function name(): string
    {
        return 'A128CCM-16-128';
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
        return 16;
    }
}
