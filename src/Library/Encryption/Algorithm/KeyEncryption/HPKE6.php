<?php

declare(strict_types=1);

namespace Jose\Component\Encryption\Algorithm\KeyEncryption;

use Jose\Component\Encryption\Algorithm\KeyEncryption\Util\HPKE\CipherSuite;
use Override;

/**
 * "HPKE-6": Integrated Encryption with HPKE using DHKEM(X448, HKDF-SHA512) KEM, HKDF-SHA512 KDF, and ChaCha20Poly1305
 * AEAD (draft-ietf-jose-hpke-encrypt section 5.1).
 */
final readonly class HPKE6 extends AbstractHPKE
{
    #[Override]
    public function name(): string
    {
        return 'HPKE-6';
    }

    #[Override]
    protected static function getCipherSuite(): CipherSuite
    {
        return CipherSuite::fromIdentifiers(0x0021, 0x0003, 0x0003);
    }
}
