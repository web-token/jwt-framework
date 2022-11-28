<?php

declare(strict_types=1);

namespace Jose\Component\Encryption\Algorithm\KeyEncryption;

use AESKW\A192KW as Wrapper;

final class A192KW extends AESKW
{
    public function name(): string
    {
        return 'A192KW';
    }

    protected function getWrapper(): Wrapper
    {
        return new Wrapper();
    }
}
