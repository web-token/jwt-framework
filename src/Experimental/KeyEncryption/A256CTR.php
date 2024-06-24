<?php

declare(strict_types=1);

namespace Jose\Experimental\KeyEncryption;

use Override;

final readonly class A256CTR extends AESCTR
{
    #[Override]
    public function name(): string
    {
        return 'A256CTR';
    }

    #[Override]
    protected function getMode(): string
    {
        return 'aes-256-ctr';
    }
}
