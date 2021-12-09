<?php

declare(strict_types=1);

namespace Jose\Component\Encryption\Algorithm\ContentEncryption;

final class A256GCM extends AESGCM
{
    public function getCEKSize(): int
    {
        return 256;
    }

    public function name(): string
    {
        return 'A256GCM';
    }

    protected function getMode(): string
    {
        return 'aes-256-gcm';
    }
}
