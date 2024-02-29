<?php

declare(strict_types=1);

namespace Jose\Experimental\ContentEncryption;

use Override;

final readonly class A128CCM_16_128 extends AESCCM
{
    #[Override]
    public function getCEKSize(): int
    {
        return 128;
    }

    #[Override]
    public function name(): string
    {
        return 'A128CCM-16-128';
    }

    #[Override]
    public function getIVSize(): int
    {
        return 13 * 8;
    }

    #[Override]
    protected function getMode(): string
    {
        return 'aes-128-ccm';
    }

    #[Override]
    protected function getTagLength(): int
    {
        return 16;
    }
}
