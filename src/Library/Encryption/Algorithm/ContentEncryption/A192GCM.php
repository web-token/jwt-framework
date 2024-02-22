<?php

declare(strict_types=1);

namespace Jose\Component\Encryption\Algorithm\ContentEncryption;

final class A192GCM extends AESGCM
{
    public function getCEKSize(): int
    {
        return 192;
    }

    public function name(): string
    {
        return 'A192GCM';
    }

    protected function getMode(): string
    {
        return 'aes-192-gcm';
    }
}
