<?php

declare(strict_types=1);

namespace Jose\Component\Encryption\Algorithm\KeyEncryption;

use Jose\Component\Encryption\Algorithm\KeyEncryption\Util\HPKE\CipherSuite;
use Override;

/**
 * "HPKE-5": Integrated Encryption with HPKE using DHKEM(X448, HKDF-SHA512) KEM, HKDF-SHA512 KDF, and AES-256-GCM AEAD
 * (draft-ietf-jose-hpke-encrypt section 5.1).
 */
final readonly class HPKE5 extends AbstractHPKE
{
    #[Override]
    public function name(): string
    {
        return 'HPKE-5';
    }

    #[Override]
    protected static function getCipherSuite(): CipherSuite
    {
        return CipherSuite::fromIdentifiers(0x0021, 0x0003, 0x0002);
    }
}
