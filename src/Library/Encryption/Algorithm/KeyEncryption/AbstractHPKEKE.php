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
use Throwable;
use function array_key_exists;
use function is_string;
use function sprintf;

/**
 * Key Encryption with HPKE (draft-ietf-jose-hpke-encrypt section 6): the CEK is the HPKE plaintext and the JWE
 * Encrypted Key is the HPKE ciphertext; the encapsulated key is the "ek" header parameter, added by the algorithm.
 * The HPKE aad is empty and the HPKE info is the Recipient_structure of section 6.1, which binds the encrypted key to
 * the content encryption algorithm: "JOSE-HPKE rcpt" || 0xFF || "enc" || 0xFF || recipient_extra_info.
 *
 * The key management mode is Key Encryption: these recipients can be combined with any other Key Encryption or Key
 * Wrapping recipient of a JWE JSON Serialization. The algorithms implement KeyAgreementWithKeyWrapping, which is what
 * HPKE does with a DH-based KEM, because that interface hands the sender key over: it is the pre-shared key of
 * mode_psk, selected by the presence of the "psk_id" header parameter; see KeyMaterial. The sender key is shared by
 * all the recipients of a JWE.
 *
 * The recipient_extra_info is empty unless mutually known private information is given to the constructor, in which
 * case the same value must be given on both sides. Each algorithm is fully-specified by its cipher suite; see
 * AbstractHPKE for the platform requirements.
 */
abstract readonly class AbstractHPKEKE implements KeyAgreementWithKeyWrapping
{
    private const RECIPIENT_STRUCTURE_CONTEXT = 'JOSE-HPKE rcpt';

    private const RECIPIENT_STRUCTURE_SEPARATOR = "\xFF";

    /**
     * @param string $recipientExtraInfo The recipient_extra_info of the Recipient_structure, empty by default
     */
    public function __construct(
        private string $recipientExtraInfo = ''
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
        return self::MODE_ENCRYPT;
    }

    /**
     * The "ek" header parameter is the output of the algorithm: a value already set in a header would replace it in
     * the token, hence is refused.
     *
     * @param array<string, mixed> $complete_header
     * @param array<string, mixed> $additional_header_values
     */
    #[Override]
    public function wrapAgreementKey(
        JWK $recipientKey,
        ?JWK $senderKey,
        string $cek,
        int $encryption_key_length,
        array $complete_header,
        array &$additional_header_values
    ): string {
        if (array_key_exists('ek', $complete_header)) {
            throw new InvalidHeaderParameterException(
                'The header parameter "ek" is computed by the algorithm and shall not be set.'
            );
        }
        $suite = static::getCipherSuite();
        [$psk, $pskId] = KeyMaterial::getPreSharedKey($senderKey, $complete_header);
        [$encapsulatedKey, $encryptedKey] = $suite->seal(
            KeyMaterial::getPublicKey($suite->kem, $recipientKey),
            $this->getRecipientStructure($complete_header),
            '',
            $cek,
            $psk,
            $pskId
        );
        $additional_header_values['ek'] = Base64UrlSafe::encodeUnpadded($encapsulatedKey);

        return $encryptedKey;
    }

    /**
     * @param array<string, mixed> $complete_header
     */
    #[Override]
    public function unwrapAgreementKey(
        JWK $recipientKey,
        ?JWK $senderKey,
        string $encrypted_cek,
        int $encryption_key_length,
        array $complete_header
    ): string {
        $suite = static::getCipherSuite();
        [$psk, $pskId] = KeyMaterial::getPreSharedKey($senderKey, $complete_header);

        return $suite->open(
            $this->getEncapsulatedKey($complete_header),
            KeyMaterial::getPrivateKey($suite->kem, $recipientKey),
            KeyMaterial::getPublicKey($suite->kem, $recipientKey),
            $this->getRecipientStructure($complete_header),
            '',
            $encrypted_cek,
            $psk,
            $pskId
        );
    }

    /**
     * The HPKE cipher suite of the algorithm.
     */
    abstract protected static function getCipherSuite(): CipherSuite;

    /**
     * @param array<string, mixed> $header
     */
    private function getRecipientStructure(array $header): string
    {
        $enc = $header['enc'] ?? null;
        if (! is_string($enc) || $enc === '') {
            throw new InvalidHeaderParameterException('The header parameter "enc" is missing.');
        }

        return self::RECIPIENT_STRUCTURE_CONTEXT
            . self::RECIPIENT_STRUCTURE_SEPARATOR
            . $enc
            . self::RECIPIENT_STRUCTURE_SEPARATOR
            . $this->recipientExtraInfo;
    }

    /**
     * @param array<string, mixed> $header
     */
    private function getEncapsulatedKey(array $header): string
    {
        $ek = $header['ek'] ?? null;
        if (! is_string($ek) || $ek === '') {
            throw new InvalidHeaderParameterException('The header parameter "ek" is missing.');
        }
        try {
            return Base64UrlSafe::decodeNoPadding($ek);
        } catch (Throwable $throwable) {
            throw new InvalidHeaderParameterException('The header parameter "ek" is invalid.', 0, $throwable);
        }
    }
}
