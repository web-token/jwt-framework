<?php

declare(strict_types=1);

namespace Jose\Component\Encryption\Algorithm\KeyEncryption;

use Jose\Component\Encryption\Algorithm\KeyEncryption\Util\HPKE\CipherSuite;
use Override;

/**
 * "HPKE-1-KE": Key Encryption with HPKE using DHKEM(P-384, HKDF-SHA384) KEM, HKDF-SHA384 KDF, and AES-256-GCM AEAD
 * (draft-ietf-jose-hpke-encrypt section 6.2).
 */
final readonly class HPKE1KE extends AbstractHPKEKE
{
    #[Override]
    public function name(): string
    {
        return 'HPKE-1-KE';
    }

    #[Override]
    protected static function getCipherSuite(): CipherSuite
    {
        return CipherSuite::fromIdentifiers(0x0011, 0x0002, 0x0002);
    }
}
