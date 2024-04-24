<?php

declare(strict_types=1);

namespace Jose\Experimental\ContentEncryption;

use Override;

final readonly class A256CCM_64_128 extends AESCCM
{
    #[Override]
    public function getCEKSize(): int
    {
        return 256;
    }

    #[Override]
    public function name(): string
    {
        return 'A256CCM-16-128';
    }

    #[Override]
    public function getIVSize(): int
    {
        return 7 * 8;
    }

    #[Override]
    protected function getMode(): string
    {
        return 'aes-256-ccm';
    }

    #[Override]
    protected function getTagLength(): int
    {
        return 16;
    }
}
