<?php

declare(strict_types=1);

namespace Jose\Component\Encryption\Algorithm\KeyEncryption;

final class A128GCMKW extends AESGCMKW
{
    public function name(): string
    {
        return 'A128GCMKW';
    }

    protected function getKeySize(): int
    {
        return 128;
    }
}
