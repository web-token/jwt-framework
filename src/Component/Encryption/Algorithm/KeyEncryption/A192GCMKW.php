<?php

declare(strict_types=1);

namespace Jose\Component\Encryption\Algorithm\KeyEncryption;

final class A192GCMKW extends AESGCMKW
{
    public function name(): string
    {
        return 'A192GCMKW';
    }

    protected function getKeySize(): int
    {
        return 192;
    }
}
