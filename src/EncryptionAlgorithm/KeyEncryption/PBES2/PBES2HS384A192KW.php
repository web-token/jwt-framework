<?php

declare(strict_types=1);

namespace Jose\Component\Encryption\Algorithm\KeyEncryption;

use AESKW\A192KW as Wrapper;

final class PBES2HS384A192KW extends PBES2AESKW
{
    public function name(): string
    {
        return 'PBES2-HS384+A192KW';
    }

    protected function getWrapper(): Wrapper
    {
        return new Wrapper();
    }

    protected function getHashAlgorithm(): string
    {
        return 'sha384';
    }

    protected function getKeySize(): int
    {
        return 24;
    }
}
