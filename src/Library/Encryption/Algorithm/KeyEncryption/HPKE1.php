<?php

declare(strict_types=1);

namespace Jose\Component\Encryption\Algorithm\KeyEncryption;

use Jose\Component\Encryption\Algorithm\KeyEncryption\Util\HPKE\CipherSuite;
use Override;

/**
 * "HPKE-1": Integrated Encryption with HPKE using DHKEM(P-384, HKDF-SHA384) KEM, HKDF-SHA384 KDF, and AES-256-GCM AEAD
 * (draft-ietf-jose-hpke-encrypt section 5.1).
 */
final readonly class HPKE1 extends AbstractHPKE
{
    #[Override]
    public function name(): string
    {
        return 'HPKE-1';
    }

    #[Override]
    protected static function getCipherSuite(): CipherSuite
    {
        return CipherSuite::fromIdentifiers(0x0011, 0x0002, 0x0002);
    }
}
