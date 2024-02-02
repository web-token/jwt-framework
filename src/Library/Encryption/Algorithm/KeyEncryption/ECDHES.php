<?php

declare(strict_types=1);

namespace Jose\Component\Encryption\Algorithm\KeyEncryption;

final class ECDHES extends AbstractECDH
{
    public function name(): string
    {
        return 'ECDH-ES';
    }
}
