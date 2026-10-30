<?php

declare(strict_types=1);

namespace Jose\Component\Encryption\Algorithm\KeyEncryption\Util\HPKE;

use Jose\Component\Core\Exception\InvalidArgumentException;
use Jose\Component\Core\Exception\InvalidKeyException;
use Jose\Component\Core\Exception\RuntimeException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Core\Util\ECKey;
use Jose\Component\Core\Util\OKPKey;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Integer;
use SpomkyLabs\Pki\ASN1\Type\Primitive\ObjectIdentifier;
use SpomkyLabs\Pki\ASN1\Type\Primitive\OctetString;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use Throwable;
use function chr;
use function function_exists;
use function in_array;
use function is_array;
use function is_string;
use function ord;
use function pack;
use function random_bytes;
use function sprintf;
use function str_pad;
use function strlen;
use function strtolower;
use function substr;
use const STR_PAD_LEFT;

/**
 * The Diffie-Hellman based KEMs of HPKE (draft-ietf-hpke-hpke sections 4.5 and 7.1) over the NIST curves P-256, P-384
 * and P-521 and over the Montgomery curves X25519 and X448.
 *
 * Keys are handled in their serialized forms: the uncompressed point for the NIST curves and the raw octet string for
 * the Montgomery curves for public keys, the big-endian scalar or the raw octet string for private keys. The ephemeral
 * key of an encapsulation is derived from Nsk random bytes, as GenerateKeyPair() is defined in section 7.1.3: the
 * test vectors of RFC 9180 give these bytes, which makes the encapsulation reproducible in tests.
 *
 * The Diffie-Hellman function is OpenSSL's for the NIST curves, which refuses a point that is not on the curve or
 * whose coordinates are out of range when it decodes it, and OKPKey's for the Montgomery curves (sodium for X25519
 * when it is loaded, OpenSSL on PHP 8.4 otherwise). An all-zero shared secret is refused on the Montgomery curves.
 *
 * @internal
 */
final readonly class DHKEM
{
    private const EC_PUBLIC_KEY_OID = '1.2.840.10045.2.1';

    /**
     * @param int $id The KEM identifier of the HPKE registry
     * @param string $curve The curve, as named in JWK
     * @param HKDF $kdf The KDF of the KEM, which may differ from the KDF of the cipher suite
     * @param int $secretLength The size of the shared secret in bytes, Nsecret
     * @param int $publicKeyLength The size of a public key and of an encapsulated key in bytes, Npk and Nenc
     * @param positive-int $privateKeyLength The size of a private key in bytes, Nsk
     * @param int $dhLength The size of a Diffie-Hellman shared secret in bytes, Ndh
     * @param string $order The order of a NIST curve as a big-endian hexadecimal string, empty for the others
     * @param int $bitmask The mask applied to the first byte of a candidate private key on a NIST curve
     */
    private function __construct(
        public int $id,
        public string $curve,
        private HKDF $kdf,
        public int $secretLength,
        public int $publicKeyLength,
        public int $privateKeyLength,
        private int $dhLength,
        private string $order = '',
        private int $bitmask = 0xFF
    ) {
    }

    public static function fromIdentifier(int $id): self
    {
        return match ($id) {
            0x0010 => self::p256(),
            0x0011 => self::p384(),
            0x0012 => self::p521(),
            0x0020 => self::x25519(),
            0x0021 => self::x448(),
            default => throw new InvalidArgumentException(sprintf('Unsupported HPKE KEM 0x%04x.', $id)),
        };
    }

    public static function p256(): self
    {
        return new self(
            0x0010,
            'P-256',
            HKDF::sha256(),
            32,
            65,
            32,
            32,
            'ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551'
        );
    }

    public static function p384(): self
    {
        return new self(
            0x0011,
            'P-384',
            HKDF::sha384(),
            48,
            97,
            48,
            48,
            'ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973'
        );
    }

    public static function p521(): self
    {
        return new self(
            0x0012,
            'P-521',
            HKDF::sha512(),
            64,
            133,
            66,
            66,
            '01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
            . 'fa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409',
            0x01
        );
    }

    public static function x25519(): self
    {
        return new self(0x0020, OKPKey::CURVE_X25519, HKDF::sha256(), 32, 32, 32, 32);
    }

    public static function x448(): self
    {
        return new self(0x0021, OKPKey::CURVE_X448, HKDF::sha512(), 64, 56, 56, 56);
    }

    /**
     * The JWK key type of the keys of this KEM.
     */
    public function keyType(): string
    {
        return $this->isMontgomeryCurve() ? 'OKP' : 'EC';
    }

    /**
     * Tells whether the platform can run this KEM: OpenSSL knows the NIST curves, the Montgomery curves need sodium
     * (X25519 only) or OpenSSL on PHP 8.4.
     */
    public function isSupported(): bool
    {
        if ($this->isMontgomeryCurve()) {
            return OKPKey::isCurveSupported($this->curve);
        }

        $curves = openssl_get_curve_names();

        return function_exists('openssl_pkey_derive') && is_array($curves) && in_array(
            $this->getOpenSSLCurveName(),
            $curves,
            true
        );
    }

    /**
     * DeriveKeyPair(ikm): rejection sampling over the scalars for the NIST curves, a single derivation for the
     * Montgomery curves, whose private keys are clamped by the Diffie-Hellman function. The candidate scalars are
     * compared with the order of the curve in constant time.
     *
     * @return array{string, string} The private key and the public key
     */
    public function deriveKeyPair(string $ikm): array
    {
        $prk = $this->kdf->labeledExtract($this->suiteId(), '', 'dkp_prk', $ikm);
        if ($this->isMontgomeryCurve()) {
            $privateKey = $this->kdf->labeledExpand($this->suiteId(), $prk, 'sk', '', $this->privateKeyLength);

            return [$privateKey, $this->getPublicKey($privateKey)];
        }
        $order = (string) hex2bin($this->order);
        for ($counter = 0; $counter < 256; ++$counter) {
            $candidate = $this->kdf->labeledExpand(
                $this->suiteId(),
                $prk,
                'candidate',
                chr($counter),
                $this->privateKeyLength
            );
            $candidate = chr(ord($candidate[0]) & $this->bitmask) . substr($candidate, 1);
            if (! self::isZero($candidate) && self::isLowerThan($candidate, $order)) {
                return [$candidate, $this->getPublicKey($candidate)];
            }
        }

        throw new RuntimeException('Unable to derive a key pair.');
    }

    /**
     * Encap(pkR): the ephemeral key pair is derived from $ikm, or from Nsk random bytes when it is not given.
     *
     * @return array{string, string} The shared secret and the encapsulated key
     */
    public function encapsulate(string $publicKey, ?string $ikm = null): array
    {
        $this->checkPublicKey($publicKey);
        [$ephemeralPrivateKey, $ephemeralPublicKey] = $this->deriveKeyPair(
            $ikm ?? random_bytes($this->privateKeyLength)
        );
        $dh = $this->computeSharedSecret($ephemeralPrivateKey, $publicKey);

        return [$this->extractAndExpand($dh, $ephemeralPublicKey . $publicKey), $ephemeralPublicKey];
    }

    /**
     * Decap(enc, skR): the public key of the recipient is part of the KEM context, in its serialized form.
     */
    public function decapsulate(string $encapsulatedKey, string $privateKey, string $publicKey): string
    {
        $this->checkPublicKey($encapsulatedKey);
        $this->checkPublicKey($publicKey);
        if (strlen($privateKey) !== $this->privateKeyLength) {
            throw new InvalidKeyException('Invalid private key.');
        }
        $dh = $this->computeSharedSecret($privateKey, $encapsulatedKey);

        return $this->extractAndExpand($dh, $encapsulatedKey . $publicKey);
    }

    private function extractAndExpand(string $dh, string $kemContext): string
    {
        $prk = $this->kdf->labeledExtract($this->suiteId(), '', 'eae_prk', $dh);

        return $this->kdf->labeledExpand($this->suiteId(), $prk, 'shared_secret', $kemContext, $this->secretLength);
    }

    private function computeSharedSecret(string $privateKey, string $publicKey): string
    {
        try {
            $dh = $this->isMontgomeryCurve() ? OKPKey::deriveSharedSecret(
                $this->createPrivateJWK($privateKey),
                $this->createPublicJWK($publicKey)
            ) : openssl_pkey_derive(
                ECKey::convertPublicKeyToPEM($this->createPublicJWK($publicKey)),
                $this->createECPrivateKeyPEM($privateKey)
            );
        } catch (Throwable $throwable) {
            throw new InvalidKeyException(
                'Unable to compute the Diffie-Hellman shared secret.',
                0,
                $throwable
            );
        }
        if (! is_string($dh) || strlen($dh) !== $this->dhLength || ($this->isMontgomeryCurve() && self::isZero(
            $dh
        ))) {
            throw new InvalidKeyException('Unable to compute the Diffie-Hellman shared secret.');
        }

        return $dh;
    }

    private function getPublicKey(string $privateKey): string
    {
        if ($this->curve === OKPKey::CURVE_X25519 && OKPKey::supportsSodium($this->curve)) {
            return sodium_crypto_scalarmult_base($privateKey);
        }
        $pem = $this->isMontgomeryCurve() ? OKPKey::convertPrivateKeyToPKCS8PEM(
            $this->createPrivateJWK($privateKey)
        ) : $this->createECPrivateKeyPEM($privateKey);
        $key = openssl_pkey_get_private($pem);
        $details = $key === false ? false : openssl_pkey_get_details($key);
        $material = is_array($details) ? ($details[$this->isMontgomeryCurve() ? strtolower(
            $this->curve
        ) : 'ec'] ?? null) : null;
        if (! is_array($material)) {
            throw new RuntimeException('Unable to compute the public key.');
        }
        if ($this->isMontgomeryCurve()) {
            $publicKey = $material['pub_key'] ?? null;
            if (! is_string($publicKey) || strlen($publicKey) !== $this->publicKeyLength) {
                throw new RuntimeException('Unable to compute the public key.');
            }

            return $publicKey;
        }
        $x = $material['x'] ?? null;
        $y = $material['y'] ?? null;
        if (! is_string($x) || ! is_string($y)) {
            throw new RuntimeException('Unable to compute the public key.');
        }

        return "\x04" . str_pad($x, $this->dhLength, "\0", STR_PAD_LEFT) . str_pad(
            $y,
            $this->dhLength,
            "\0",
            STR_PAD_LEFT
        );
    }

    /**
     * The public keys of the NIST curves are uncompressed points, the only encoding of section 7.1.1. The point
     * itself is validated by OpenSSL when it is decoded.
     */
    private function checkPublicKey(string $publicKey): void
    {
        if (strlen($publicKey) !== $this->publicKeyLength) {
            throw new InvalidKeyException('Invalid public key.');
        }
        if (! $this->isMontgomeryCurve() && $publicKey[0] !== "\x04") {
            throw new InvalidKeyException('Invalid public key.');
        }
    }

    private function createPublicJWK(string $publicKey): JWK
    {
        if ($this->isMontgomeryCurve()) {
            return new JWK([
                'kty' => 'OKP',
                'crv' => $this->curve,
                'x' => Base64UrlSafe::encodeUnpadded($publicKey),
            ]);
        }

        return new JWK([
            'kty' => 'EC',
            'crv' => $this->curve,
            'x' => Base64UrlSafe::encodeUnpadded(substr($publicKey, 1, $this->dhLength)),
            'y' => Base64UrlSafe::encodeUnpadded(substr($publicKey, 1 + $this->dhLength)),
        ]);
    }

    private function createPrivateJWK(string $privateKey): JWK
    {
        return new JWK([
            'kty' => 'OKP',
            'crv' => $this->curve,
            'd' => Base64UrlSafe::encodeUnpadded($privateKey),
        ]);
    }

    /**
     * A PKCS#8 structure holding the scalar alone: OpenSSL computes the public key when it loads it.
     */
    private function createECPrivateKeyPEM(string $privateKey): string
    {
        $privateKeyInfo = Sequence::create(
            Integer::create(0),
            Sequence::create(
                ObjectIdentifier::create(self::EC_PUBLIC_KEY_OID),
                ObjectIdentifier::create($this->getCurveOid())
            ),
            OctetString::create(Sequence::create(Integer::create(1), OctetString::create($privateKey))->toDER())
        );

        return PEM::create(PEM::TYPE_PRIVATE_KEY, $privateKeyInfo->toDER())
            ->string();
    }

    private function getCurveOid(): string
    {
        return match ($this->curve) {
            'P-256' => '1.2.840.10045.3.1.7',
            'P-384' => '1.3.132.0.34',
            default => '1.3.132.0.35',
        };
    }

    private function getOpenSSLCurveName(): string
    {
        return match ($this->curve) {
            'P-256' => 'prime256v1',
            'P-384' => 'secp384r1',
            default => 'secp521r1',
        };
    }

    private function isMontgomeryCurve(): bool
    {
        return $this->curve === OKPKey::CURVE_X25519 || $this->curve === OKPKey::CURVE_X448;
    }

    private function suiteId(): string
    {
        return 'KEM' . pack('n', $this->id);
    }

    private static function isZero(string $value): bool
    {
        $accumulator = 0;
        $length = strlen($value);
        for ($i = 0; $i < $length; ++$i) {
            $accumulator |= ord($value[$i]);
        }

        return $accumulator === 0;
    }

    /**
     * Compares two big-endian integers of the same size in constant time: the borrow of $left - $right, computed
     * from the least significant byte, is set when $left is lower.
     */
    private static function isLowerThan(string $left, string $right): bool
    {
        $borrow = 0;
        for ($i = strlen($left) - 1; $i >= 0; --$i) {
            $borrow = ((ord($left[$i]) - ord($right[$i]) - $borrow) >> 8) & 1;
        }

        return $borrow === 1;
    }
}
