<?php

declare(strict_types=1);

namespace Jose\Component\Encryption\Algorithm\KeyEncryption;

use AESKW\A256KW as Wrapper;

final class PBES2HS512A256KW extends PBES2AESKW
{
    public function name(): string
    {
        return 'PBES2-HS512+A256KW';
    }

    protected function getWrapper(): Wrapper
    {
        return new Wrapper();
    }

    protected function getHashAlgorithm(): string
    {
        return 'sha512';
    }

    protected function getKeySize(): int
    {
        return 32;
    }
}
