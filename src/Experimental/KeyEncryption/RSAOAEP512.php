<?php

declare(strict_types=1);

namespace Jose\Experimental\KeyEncryption;

use Jose\Component\Encryption\Algorithm\KeyEncryption\RSA;
use Jose\Component\Encryption\Algorithm\KeyEncryption\Util\RSACrypt;
use Override;

final readonly class RSAOAEP512 extends RSA
{
    #[Override]
    public function getEncryptionMode(): int
    {
        return RSACrypt::ENCRYPTION_OAEP;
    }

    #[Override]
    public function getHashAlgorithm(): string
    {
        return 'sha512';
    }

    #[Override]
    public function name(): string
    {
        return 'RSA-OAEP-512';
    }
}
