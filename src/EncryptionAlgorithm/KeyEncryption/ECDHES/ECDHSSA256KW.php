<?php

declare(strict_types=1);

namespace Jose\Component\Encryption\Algorithm\KeyEncryption;

use AESKW\A256KW as Wrapper;

final class ECDHSSA256KW extends ECDHSSAESKW
{
    /**
     * NOTE: the return name was modified
     */
    public function name(): string
    {
        return 'ECDH-SS+A256KW';
    }

    protected function getWrapper(): Wrapper
    {
        return new Wrapper();
    }

    protected function getKeyLength(): int
    {
        return 256;
    }
}
