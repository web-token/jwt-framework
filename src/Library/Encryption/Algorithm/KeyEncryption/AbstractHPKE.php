<?php

declare(strict_types=1);

namespace Jose\Component\Encryption\Algorithm\KeyEncryption;

use Jose\Component\Core\Exception\InvalidHeaderParameterException;
use Jose\Component\Core\Exception\MissingDependencyException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Encryption\Algorithm\KeyEncryption\Util\HPKE\CipherSuite;
use Jose\Component\Encryption\Algorithm\KeyEncryption\Util\HPKE\KeyMaterial;
use Override;
use function array_key_exists;
use function sprintf;

/**
 * Integrated Encryption with HPKE (draft-ietf-jose-hpke-encrypt section 5): the payload is the HPKE plaintext, the
 * JWE Encrypted Key is the encapsulated key and the JWE Ciphertext is the HPKE ciphertext, authentication tag
 * included. The HPKE aad is the additional authenticated data of RFC 7516, which binds the protected header and the
 * JWE AAD to the ciphertext. The "ek" header parameter is not used in this mode.
 *
 * The HPKE info is empty unless mutually known private information is given to the constructor, in which case the
 * same value must be given on both sides. The mode is mode_psk when the "psk_id" header parameter is present, the
 * pre-shared key being the sender key given to the builder and to the decrypter; see KeyMaterial.
 *
 * Each algorithm is fully-specified by its cipher suite. The platform needs OpenSSL for the NIST curves and AES-GCM,
 * sodium or OpenSSL on PHP 8.4 for X25519, OpenSSL on PHP 8.4 for X448 and an OpenSSL providing ChaCha20Poly1305
 * for the suites using it: isSupported() tells, and the constructor throws when the platform cannot run the
 * algorithm.
 */
abstract readonly class AbstractHPKE implements IntegratedEncryption
{
    /**
     * @param string $info The HPKE info, the empty octet sequence by default
     */
    public function __construct(
        private string $info = ''
    ) {
        if (! static::isSupported()) {
            throw new MissingDependencyException(sprintf(
                'The algorithm "%s" is not supported by this platform.',
                $this->name()
            ));
        }
    }

    /**
     * Tells whether the platform can run this algorithm. The constructor throws when it cannot, so that a service
     * container or an algorithm manager can skip the algorithm instead of failing at the first encryption.
     */
    public static function isSupported(): bool
    {
        return static::getCipherSuite()->isSupported();
    }

    #[Override]
    public function allowedKeyTypes(): array
    {
        return [static::getCipherSuite()->kem->keyType()];
    }

    #[Override]
    public function getKeyManagementMode(): string
    {
        return self::MODE_INTEGRATED;
    }

    /**
     * @param array<string, mixed> $completeHeader
     */
    #[Override]
    public function encryptPayload(
        JWK $recipientKey,
        ?JWK $senderKey,
        string $payload,
        ?string $aad,
        string $encodedProtectedHeader,
        array $completeHeader
    ): EncryptedPayload {
        $this->checkHeader($completeHeader);
        $suite = static::getCipherSuite();
        [$psk, $pskId] = KeyMaterial::getPreSharedKey($senderKey, $completeHeader);
        [$encapsulatedKey, $ciphertext] = $suite->seal(
            KeyMaterial::getPublicKey($suite->kem, $recipientKey),
            $this->info,
            self::getAdditionalAuthenticatedData($aad, $encodedProtectedHeader),
            $payload,
            $psk,
            $pskId
        );

        return new EncryptedPayload($encapsulatedKey, $ciphertext);
    }

    /**
     * @param array<string, mixed> $completeHeader
     */
    #[Override]
    public function decryptPayload(
        JWK $recipientKey,
        ?JWK $senderKey,
        string $encryptedKey,
        string $ciphertext,
        ?string $aad,
        string $encodedProtectedHeader,
        array $completeHeader
    ): string {
        $this->checkHeader($completeHeader);
        $suite = static::getCipherSuite();
        [$psk, $pskId] = KeyMaterial::getPreSharedKey($senderKey, $completeHeader);

        return $suite->open(
            $encryptedKey,
            KeyMaterial::getPrivateKey($suite->kem, $recipientKey),
            KeyMaterial::getPublicKey($suite->kem, $recipientKey),
            $this->info,
            self::getAdditionalAuthenticatedData($aad, $encodedProtectedHeader),
            $ciphertext,
            $psk,
            $pskId
        );
    }

    /**
     * The HPKE cipher suite of the algorithm.
     */
    abstract protected static function getCipherSuite(): CipherSuite;

    /**
     * @param array<string, mixed> $completeHeader
     */
    private function checkHeader(array $completeHeader): void
    {
        if (array_key_exists('ek', $completeHeader)) {
            throw new InvalidHeaderParameterException(sprintf(
                'The header parameter "ek" shall not be set with the algorithm "%s".',
                $this->name()
            ));
        }
    }

    private static function getAdditionalAuthenticatedData(?string $aad, string $encodedProtectedHeader): string
    {
        if ($aad === null) {
            return $encodedProtectedHeader;
        }

        return $encodedProtectedHeader . '.' . Base64UrlSafe::encodeUnpadded($aad);
    }
}
