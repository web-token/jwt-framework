<?php

declare(strict_types=1);

namespace Jose\Component\Encryption\Algorithm\KeyEncryption\Util\HPKE;

use Jose\Component\Core\Exception\InvalidArgumentException;
use function chr;
use function pack;
use function strlen;

/**
 * An HPKE cipher suite (KEM, KDF, AEAD) and the single-shot encryption and decryption of draft-ietf-hpke-hpke
 * section 6.1, in the two modes the draft keeps: mode_base and mode_psk, the latter being selected by a non-empty
 * pre-shared key. Only the first encryption of a context is ever computed, so the nonce is the base nonce.
 *
 * This is the minimal subset draft-ietf-jose-hpke-encrypt needs: no export interface, no multi-message context, no
 * Auth or AuthPSK modes (both removed from draft-ietf-hpke-hpke).
 *
 * @internal
 */
final readonly class CipherSuite
{
    private const MODE_BASE = 0x00;

    private const MODE_PSK = 0x01;

    /**
     * The minimum size of a pre-shared key: the draft requires 32 bytes of entropy (section 5.1.2).
     */
    private const PSK_MIN_LENGTH = 32;

    public function __construct(
        public DHKEM $kem,
        public HKDF $kdf,
        public AEAD $aead
    ) {
    }

    public static function fromIdentifiers(int $kemId, int $kdfId, int $aeadId): self
    {
        return new self(DHKEM::fromIdentifier($kemId), HKDF::fromIdentifier($kdfId), AEAD::fromIdentifier($aeadId));
    }

    public function isSupported(): bool
    {
        return $this->kem->isSupported() && $this->aead->isSupported();
    }

    /**
     * Seal<MODE>(pkR, info, aad, pt, ...): the ephemeral key is derived from $ikm when given, which only the test
     * vectors do.
     *
     * @return array{string, string} The encapsulated key and the ciphertext
     */
    public function seal(
        string $publicKey,
        string $info,
        string $aad,
        string $plaintext,
        string $psk = '',
        string $pskId = '',
        ?string $ikm = null
    ): array {
        $this->checkPreSharedKeyInputs($psk, $pskId);
        [$sharedSecret, $encapsulatedKey] = $this->kem->encapsulate($publicKey, $ikm);
        [$key, $nonce] = $this->keySchedule($sharedSecret, $info, $psk, $pskId);

        return [$encapsulatedKey, $this->aead->seal($key, $nonce, $aad, $plaintext)];
    }

    /**
     * Open<MODE>(enc, skR, info, aad, ct, ...): the public key of the recipient is needed by the KEM context.
     */
    public function open(
        string $encapsulatedKey,
        string $privateKey,
        string $publicKey,
        string $info,
        string $aad,
        string $ciphertext,
        string $psk = '',
        string $pskId = ''
    ): string {
        $this->checkPreSharedKeyInputs($psk, $pskId);
        $sharedSecret = $this->kem->decapsulate($encapsulatedKey, $privateKey, $publicKey);
        [$key, $nonce] = $this->keySchedule($sharedSecret, $info, $psk, $pskId);

        return $this->aead->open($key, $nonce, $aad, $ciphertext);
    }

    /**
     * KeySchedule<ROLE>() with a two-stage KDF (section 5.1): the AEAD key and the base nonce of the context.
     *
     * @return array{string, string} The key and the base nonce
     */
    public function keySchedule(string $sharedSecret, string $info, string $psk, string $pskId): array
    {
        $this->checkPreSharedKeyInputs($psk, $pskId);
        $suiteId = 'HPKE' . pack('nnn', $this->kem->id, $this->kdf->id, $this->aead->id);
        $context = chr($psk === '' ? self::MODE_BASE : self::MODE_PSK)
            . $this->kdf->labeledExtract($suiteId, '', 'psk_id_hash', $pskId)
            . $this->kdf->labeledExtract($suiteId, '', 'info_hash', $info);
        $secret = $this->kdf->labeledExtract($suiteId, $sharedSecret, 'secret', $psk);

        return [
            $this->kdf->labeledExpand($suiteId, $secret, 'key', $context, $this->aead->keyLength),
            $this->kdf->labeledExpand($suiteId, $secret, 'base_nonce', $context, $this->aead->nonceLength),
        ];
    }

    /**
     * VerifyPSKInputs(): the pre-shared key and its identifier come together or not at all, and the key is long
     * enough.
     */
    private function checkPreSharedKeyInputs(string $psk, string $pskId): void
    {
        if (($psk === '') !== ($pskId === '')) {
            throw new InvalidArgumentException(
                'The pre-shared key and its identifier shall be given together or not at all.'
            );
        }
        if ($psk !== '' && strlen($psk) < self::PSK_MIN_LENGTH) {
            throw new InvalidArgumentException('The pre-shared key shall be at least 32 bytes long.');
        }
    }
}
