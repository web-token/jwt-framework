<?php

declare(strict_types=1);

namespace Jose\Experimental\KeyEncryption;

use Override;

final readonly class A192CTR extends AESCTR
{
    #[Override]
    public function name(): string
    {
        return 'A192CTR';
    }

    #[Override]
    protected function getMode(): string
    {
        return 'aes-192-ctr';
    }
}
