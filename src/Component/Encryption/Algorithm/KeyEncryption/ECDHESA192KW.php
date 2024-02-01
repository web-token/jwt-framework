<?php

declare(strict_types=1);

namespace Jose\Component\Encryption\Algorithm\KeyEncryption;

use AESKW\A192KW as Wrapper;

final class ECDHESA192KW extends ECDHESAESKW
{
    public function name(): string
    {
        return 'ECDH-ES+A192KW';
    }

    protected function getWrapper(): Wrapper
    {
        return new Wrapper();
    }

    protected function getKeyLength(): int
    {
        return 192;
    }
}
