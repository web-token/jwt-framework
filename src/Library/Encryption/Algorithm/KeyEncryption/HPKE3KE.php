<?php

declare(strict_types=1);

namespace Jose\Component\Encryption\Algorithm\KeyEncryption;

use Jose\Component\Encryption\Algorithm\KeyEncryption\Util\HPKE\CipherSuite;
use Override;

/**
 * "HPKE-3-KE": Key Encryption with HPKE using DHKEM(X25519, HKDF-SHA256) KEM, HKDF-SHA256 KDF, and AES-128-GCM AEAD
 * (draft-ietf-jose-hpke-encrypt section 6.2).
 */
final readonly class HPKE3KE extends AbstractHPKEKE
{
    #[Override]
    public function name(): string
    {
        return 'HPKE-3-KE';
    }

    #[Override]
    protected static function getCipherSuite(): CipherSuite
    {
        return CipherSuite::fromIdentifiers(0x0020, 0x0001, 0x0001);
    }
}
