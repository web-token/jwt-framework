<?php

declare(strict_types=1);

namespace Jose\Component\Core\Util;

use Jose\Component\Core\Exception\InvalidKeyException;
use Jose\Component\Core\Exception\MissingDependencyException;
use Jose\Component\Core\Exception\RuntimeException;
use Jose\Component\Core\Exception\UnsupportedCurveException;
use Jose\Component\Core\JWK;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKeyInfo;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PublicKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\RFC8410\Curve25519\Ed25519PrivateKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\RFC8410\Curve25519\Ed25519PublicKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\RFC8410\Curve25519\X25519PrivateKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\RFC8410\Curve25519\X25519PublicKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\RFC8410\Curve448\Ed448PrivateKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\RFC8410\Curve448\Ed448PublicKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\RFC8410\Curve448\X448PrivateKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\RFC8410\Curve448\X448PublicKey;
use function extension_loaded;
use function in_array;
use function is_array;
use function is_string;
use function sprintf;
use function strlen;
use const PHP_VERSION_ID;

/**
 * Octet Key Pair keys (RFC 8037): conversion into the PEM structures defined by RFC 8410, key generation and
 * Diffie-Hellman over the Montgomery curves.
 *
 * Two backends serve the four curves. ext-sodium knows Ed25519 and X25519 only and is preferred for them, as it was
 * the only backend until 4.3. ext-openssl knows the four curves, but PHP exposes the raw key material and the
 * digest-less signature of the Edwards curves since 8.4 only: on 8.2 and 8.3, openssl_pkey_get_details() returns no
 * "ed448" member and openssl_sign() refuses a null digest. Ed448 and X448 are therefore available on PHP 8.4 and
 * later, whatever the OpenSSL version, and Ed25519 / X25519 work without sodium from that version too.
 *
 * @internal
 */
final readonly class OKPKey
{
    public const CURVE_ED25519 = 'Ed25519';

    public const CURVE_ED448 = 'Ed448';

    public const CURVE_X25519 = 'X25519';

    public const CURVE_X448 = 'X448';

    /**
     * The size in bytes of the "x" and "d" parameters of each curve (RFC 8032 section 5, RFC 7748 section 5).
     */
    public const KEY_SIZES = [
        self::CURVE_ED25519 => 32,
        self::CURVE_ED448 => 57,
        self::CURVE_X25519 => 32,
        self::CURVE_X448 => 56,
    ];

    /**
     * The OpenSSL key type of each curve, as numbered by ext-openssl. The OPENSSL_KEYTYPE_* constants only exist
     * since PHP 8.4, which is also the first version able to use them.
     */
    private const OPENSSL_KEY_TYPES = [
        self::CURVE_X25519 => 4,
        self::CURVE_ED25519 => 5,
        self::CURVE_X448 => 6,
        self::CURVE_ED448 => 7,
    ];

    /**
     * The member of openssl_pkey_get_details() that carries the raw key material of each curve.
     */
    private const OPENSSL_DETAILS_KEYS = [
        self::CURVE_X25519 => 'x25519',
        self::CURVE_ED25519 => 'ed25519',
        self::CURVE_X448 => 'x448',
        self::CURVE_ED448 => 'ed448',
    ];

    /**
     * Tells whether ext-openssl can generate, sign with, verify with and derive from OKP keys on this platform.
     */
    public static function supportsOpenSSL(): bool
    {
        return PHP_VERSION_ID >= 80400 && extension_loaded('openssl');
    }

    /**
     * Tells whether ext-sodium can serve the given curve: it only knows Ed25519 and X25519.
     */
    public static function supportsSodium(string $curve): bool
    {
        return extension_loaded('sodium') && in_array($curve, [self::CURVE_ED25519, self::CURVE_X25519], true);
    }

    /**
     * Tells whether the given curve can be used on this platform, with either backend.
     */
    public static function isCurveSupported(string $curve): bool
    {
        return self::supportsSodium($curve) || (self::supportsOpenSSL() && isset(self::KEY_SIZES[$curve]));
    }

    /**
     * Generates a private key on the given curve, with sodium when it knows the curve and OpenSSL otherwise.
     */
    public static function generate(string $curve): JWK
    {
        if (! isset(self::KEY_SIZES[$curve])) {
            throw new UnsupportedCurveException(sprintf('Unsupported "%s" curve', $curve));
        }
        if (self::supportsSodium($curve)) {
            return self::generateWithSodium($curve);
        }
        if (self::supportsOpenSSL()) {
            return self::generateWithOpenSSL($curve);
        }

        throw new MissingDependencyException(sprintf(
            'The curve "%s" needs the extension "sodium", or the extension "openssl" on PHP 8.4 or later.',
            $curve
        ));
    }

    /**
     * Generates a private key on the given curve with OpenSSL. Needs PHP 8.4, see supportsOpenSSL().
     */
    public static function generateWithOpenSSL(string $curve): JWK
    {
        if (! isset(self::OPENSSL_KEY_TYPES[$curve])) {
            throw new UnsupportedCurveException(sprintf('Unsupported "%s" curve', $curve));
        }
        $key = openssl_pkey_new([
            'private_key_type' => self::OPENSSL_KEY_TYPES[$curve],
        ]);
        $details = $key === false ? false : openssl_pkey_get_details($key);
        $material = is_array($details) ? ($details[self::OPENSSL_DETAILS_KEYS[$curve]] ?? null) : null;
        if (! is_array($material) || ! is_string($material['pub_key'] ?? null) || ! is_string(
            $material['priv_key'] ?? null
        )) {
            throw new RuntimeException(sprintf('Unable to generate a key on the "%s" curve.', $curve));
        }

        return self::createKey($curve, $material['pub_key'], $material['priv_key']);
    }

    /**
     * Signs the input with the private key, with OpenSSL (PureEdDSA, RFC 8032). Needs PHP 8.4, see
     * supportsOpenSSL(): before that version openssl_sign() refuses the null digest the Edwards curves require.
     *
     * @return non-empty-string
     */
    public static function signWithOpenSSL(JWK $privateKey, string $input): string
    {
        $key = openssl_pkey_get_private(self::convertPrivateKeyToPKCS8PEM($privateKey));
        if ($key === false) {
            throw new InvalidKeyException('Unable to load the private key.');
        }
        $signature = '';
        if (! openssl_sign($input, $signature, $key, 0) || ! is_string($signature) || $signature === '') {
            throw new RuntimeException('Unable to sign the input.');
        }

        return $signature;
    }

    /**
     * Verifies the signature of the input with the public key, with OpenSSL (PureEdDSA, RFC 8032). Needs PHP 8.4,
     * see supportsOpenSSL(). A malformed signature is false, not an exception.
     */
    public static function verifyWithOpenSSL(JWK $publicKey, string $input, string $signature): bool
    {
        $key = openssl_pkey_get_public(self::convertPublicKeyToPEM($publicKey));
        if ($key === false) {
            throw new InvalidKeyException('Unable to load the public key.');
        }

        return openssl_verify($input, $signature, $key, 0) === 1;
    }

    /**
     * Computes the Diffie-Hellman shared secret of a private and a public key on the same Montgomery curve
     * (RFC 7748 section 6): sodium for X25519 when loaded, OpenSSL otherwise.
     */
    public static function deriveSharedSecret(JWK $privateKey, JWK $publicKey): string
    {
        $curve = self::getParameter($publicKey, 'crv');
        if (! in_array($curve, [self::CURVE_X25519, self::CURVE_X448], true)) {
            throw new UnsupportedCurveException(sprintf('The curve "%s" is not supported', $curve));
        }
        if (self::getParameter($privateKey, 'crv') !== $curve) {
            throw new InvalidKeyException('Curves are different');
        }
        if (self::supportsSodium($curve)) {
            return sodium_crypto_scalarmult(
                Base64UrlSafe::decodeNoPadding(self::getParameter($privateKey, 'd')),
                Base64UrlSafe::decodeNoPadding(self::getParameter($publicKey, 'x'))
            );
        }
        if (! self::supportsOpenSSL()) {
            throw new MissingDependencyException(sprintf(
                'The curve "%s" needs the extension "sodium", or the extension "openssl" on PHP 8.4 or later.',
                $curve
            ));
        }

        return self::deriveSharedSecretWithOpenSSL($privateKey, $publicKey);
    }

    /**
     * Computes the Diffie-Hellman shared secret with OpenSSL. Needs PHP 8.4, see supportsOpenSSL().
     */
    public static function deriveSharedSecretWithOpenSSL(JWK $privateKey, JWK $publicKey): string
    {
        $curve = self::getParameter($publicKey, 'crv');
        if (! isset(self::KEY_SIZES[$curve])) {
            throw new UnsupportedCurveException(sprintf('The curve "%s" is not supported', $curve));
        }
        $secret = openssl_pkey_derive(
            self::convertPublicKeyToPEM($publicKey),
            self::convertPrivateKeyToPKCS8PEM($privateKey)
        );
        if (! is_string($secret) || strlen($secret) !== self::KEY_SIZES[$curve]) {
            throw new RuntimeException('Unable to derive the key');
        }

        return $secret;
    }

    /**
     * Converts the key into a PKCS#8 PEM. As PKCS#8 only covers private keys, public keys are converted into a
     * SubjectPublicKeyInfo structure, which is the format expected by the tools consuming PKCS#8 private keys.
     */
    public static function convertToPKCS8PEM(JWK $jwk): string
    {
        if ($jwk->has('d')) {
            return self::convertPrivateKeyToPKCS8PEM($jwk);
        }

        return self::convertPublicKeyToPEM($jwk);
    }

    /**
     * Converts the private key into a PKCS#8 (RFC 5208) PEM. The public key is deliberately left out of the structure:
     * the resulting OneAsymmetricKey stays at version 0, which is what RFC 8410 section 7 recommends and what the
     * widely deployed PKCS#8 parsers expect.
     */
    public static function convertPrivateKeyToPKCS8PEM(JWK $jwk): string
    {
        $privateKey = self::createPrivateKey($jwk);

        return PrivateKeyInfo::create($privateKey->algorithmIdentifier(), $privateKey->toDER())
            ->toPEM()
            ->string();
    }

    /**
     * Converts the public key into a SubjectPublicKeyInfo (RFC 5280) PEM.
     */
    public static function convertPublicKeyToPEM(JWK $jwk): string
    {
        return self::createPublicKey($jwk)
            ->publicKeyInfo()
            ->toPEM()
            ->string();
    }

    private static function createPrivateKey(JWK $jwk): PrivateKey
    {
        $curve = self::getParameter($jwk, 'crv');
        $d = Base64UrlSafe::decodeNoPadding(self::getParameter($jwk, 'd'));

        return match ($curve) {
            'Ed25519' => Ed25519PrivateKey::create($d),
            'Ed448' => Ed448PrivateKey::create($d),
            'X25519' => X25519PrivateKey::create($d),
            'X448' => X448PrivateKey::create($d),
            default => throw new UnsupportedCurveException(sprintf('The curve "%s" is not supported.', $curve)),
        };
    }

    private static function createPublicKey(JWK $jwk): PublicKey
    {
        $curve = self::getParameter($jwk, 'crv');
        $x = Base64UrlSafe::decodeNoPadding(self::getParameter($jwk, 'x'));

        return match ($curve) {
            'Ed25519' => Ed25519PublicKey::create($x),
            'Ed448' => Ed448PublicKey::create($x),
            'X25519' => X25519PublicKey::create($x),
            'X448' => X448PublicKey::create($x),
            default => throw new UnsupportedCurveException(sprintf('The curve "%s" is not supported.', $curve)),
        };
    }

    private static function generateWithSodium(string $curve): JWK
    {
        if ($curve === self::CURVE_X25519) {
            $keyPair = sodium_crypto_box_keypair();

            return self::createKey(
                $curve,
                sodium_crypto_box_publickey($keyPair),
                sodium_crypto_box_secretkey($keyPair)
            );
        }
        $keyPair = sodium_crypto_sign_keypair();
        $secret = sodium_crypto_sign_secretkey($keyPair);

        return self::createKey(
            $curve,
            sodium_crypto_sign_publickey($keyPair),
            substr($secret, 0, -(int) (strlen($secret) / 2))
        );
    }

    private static function createKey(string $curve, string $x, string $d): JWK
    {
        return new JWK([
            'kty' => 'OKP',
            'crv' => $curve,
            'x' => Base64UrlSafe::encodeUnpadded($x),
            'd' => Base64UrlSafe::encodeUnpadded($d),
        ]);
    }

    private static function getParameter(JWK $jwk, string $parameter): string
    {
        $value = $jwk->get($parameter);
        if (! is_string($value)) {
            throw new InvalidKeyException(sprintf('Unable to get the "%s" parameter', $parameter));
        }

        return $value;
    }
}
