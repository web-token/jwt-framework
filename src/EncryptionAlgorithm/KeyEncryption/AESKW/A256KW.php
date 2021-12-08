<?php

declare(strict_types=1);

namespace Jose\Component\Encryption\Algorithm\KeyEncryption;

use AESKW\A256KW as Wrapper;
use AESKW\Wrapper as WrapperInterface;

final class A256KW extends AESKW
{
    public function name(): string
    {
        return 'A256KW';
    }

    protected function getWrapper(): WrapperInterface
    {
        return new Wrapper();
    }
}
