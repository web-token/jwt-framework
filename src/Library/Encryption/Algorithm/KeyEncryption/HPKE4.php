<?php

declare(strict_types=1);

namespace Jose\Component\Encryption\Algorithm\KeyEncryption;

use Jose\Component\Encryption\Algorithm\KeyEncryption\Util\HPKE\CipherSuite;
use Override;

/**
 * "HPKE-4": Integrated Encryption with HPKE using DHKEM(X25519, HKDF-SHA256) KEM, HKDF-SHA256 KDF, and ChaCha20Poly1305
 * AEAD (draft-ietf-jose-hpke-encrypt section 5.1).
 */
final readonly class HPKE4 extends AbstractHPKE
{
    #[Override]
    public function name(): string
    {
        return 'HPKE-4';
    }

    #[Override]
    protected static function getCipherSuite(): CipherSuite
    {
        return CipherSuite::fromIdentifiers(0x0020, 0x0001, 0x0003);
    }
}
