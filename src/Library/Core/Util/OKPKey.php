<?php

declare(strict_types=1);

namespace Jose\Component\Core\Util;

use InvalidArgumentException;
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
use function is_string;
use function sprintf;

/**
 * Converts Octet Key Pair keys (RFC 8037) into the PEM structures defined by RFC 8410.
 *
 * @internal
 */
final readonly class OKPKey
{
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
            default => throw new InvalidArgumentException(sprintf('The curve "%s" is not supported.', $curve)),
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
            default => throw new InvalidArgumentException(sprintf('The curve "%s" is not supported.', $curve)),
        };
    }

    private static function getParameter(JWK $jwk, string $parameter): string
    {
        $value = $jwk->get($parameter);
        if (! is_string($value)) {
            throw new InvalidArgumentException(sprintf('Unable to get the "%s" parameter', $parameter));
        }

        return $value;
    }
}
