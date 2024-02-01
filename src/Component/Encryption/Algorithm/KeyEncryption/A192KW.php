<?php

declare(strict_types=1);

namespace Jose\Component\Encryption\Algorithm\KeyEncryption;

use AESKW\A192KW as Wrapper;
use AESKW\Wrapper as WrapperInterface;

final class A192KW extends AESKW
{
    public function name(): string
    {
        return 'A192KW';
    }

    protected function getWrapper(): WrapperInterface
    {
        return new Wrapper();
    }
}
