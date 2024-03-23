<?php

declare(strict_types=1);

namespace Jose\Experimental\KeyEncryption;

use Override;

final readonly class A128CTR extends AESCTR
{
    #[Override]
    public function name(): string
    {
        return 'A128CTR';
    }

    #[Override]
    protected function getMode(): string
    {
        return 'aes-128-ctr';
    }
}
