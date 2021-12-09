<?php

declare(strict_types=1);

namespace Jose\Component\Encryption\Algorithm\ContentEncryption;

final class A128GCM extends AESGCM
{
    public function getCEKSize(): int
    {
        return 128;
    }

    public function name(): string
    {
        return 'A128GCM';
    }

    protected function getMode(): string
    {
        return 'aes-128-gcm';
    }
}
