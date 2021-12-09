<?php

declare(strict_types=1);

namespace Jose\Component\Encryption\Algorithm\KeyEncryption;

final class A128CTR extends AESCTR
{
    public function name(): string
    {
        return 'A128CTR';
    }

    protected function getMode(): string
    {
        return 'aes-128-ctr';
    }
}
