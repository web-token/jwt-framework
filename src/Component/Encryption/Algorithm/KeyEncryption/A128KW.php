<?php

declare(strict_types=1);

namespace Jose\Component\Encryption\Algorithm\KeyEncryption;

use AESKW\A128KW as Wrapper;
use AESKW\Wrapper as WrapperInterface;

final class A128KW extends AESKW
{
    public function name(): string
    {
        return 'A128KW';
    }

    protected function getWrapper(): WrapperInterface
    {
        return new Wrapper();
    }
}
