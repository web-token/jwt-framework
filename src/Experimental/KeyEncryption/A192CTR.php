<?php

declare(strict_types=1);

namespace Jose\Experimental\KeyEncryption;

final class A192CTR extends AESCTR
{
    public function name(): string
    {
        return 'A192CTR';
    }

    protected function getMode(): string
    {
        return 'aes-192-ctr';
    }
}
