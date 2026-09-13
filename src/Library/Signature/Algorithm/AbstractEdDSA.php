<?php

declare(strict_types=1);

namespace Jose\Component\Signature\Algorithm;

use Jose\Component\Core\Exception\InvalidArgumentException;
use Jose\Component\Core\Exception\InvalidKeyException;
use Jose\Component\Core\Exception\MissingDependencyException;
use Jose\Component\Core\Exception\RuntimeException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Core\Util\OKPKey;
use Override;
use ParagonIE\Sodium\Core\Ed25519 as SodiumEd25519;
use function in_array;
use function is_string;
use function sprintf;
use function strlen;

/**
 * PureEdDSA over an Edwards curve, as used by JWS (RFC 8037 section 3.1): no pre-hash and an empty context.
 *
 * A concrete algorithm names the curve it accepts. The fully-specified "Ed25519" and "Ed448" of RFC 9864 each accept
 * one curve; the polymorphic "EdDSA" still exists for the tokens already in circulation and keeps accepting Ed25519
 * only, as it did before 4.3.
 *
 * Ed25519 is signed with sodium when the extension is loaded, as before, and with OpenSSL otherwise; Ed448 is
 * OpenSSL only. Both OpenSSL paths need PHP 8.4, see OKPKey::supportsOpenSSL(). A signature of the wrong length is
 * rejected before any backend is called, so that a malformed or tampered signature is "false", never an exception.
 */
abstract readonly class AbstractEdDSA implements SignatureAlgorithm
{
    /**
     * The size in bytes of a signature on each curve (RFC 8032 sections 5.1.6 and 5.2.6).
     */
    private const SIGNATURE_SIZES = [
        OKPKey::CURVE_ED25519 => 64,
        OKPKey::CURVE_ED448 => 114,
    ];

    public function __construct()
    {
        if (! static::isSupported()) {
            throw new MissingDependencyException(sprintf(
                static::curve() === OKPKey::CURVE_ED25519
                    ? 'The algorithm "%s" needs the extension "sodium", or the extension "openssl" on PHP 8.4 or later.'
                    : 'The algorithm "%s" needs the extension "openssl" on PHP 8.4 or later.',
                $this->name()
            ));
        }
    }

    /**
     * Tells whether the platform can run this algorithm. The constructor throws when it cannot, so that a service
     * container or an algorithm manager can skip the algorithm instead of failing at the first signature.
     */
    public static function isSupported(): bool
    {
        return OKPKey::isCurveSupported(static::curve());
    }

    #[Override]
    public function allowedKeyTypes(): array
    {
        return ['OKP'];
    }

    /**
     * @return non-empty-string
     */
    #[Override]
    public function sign(JWK $key, string $input): string
    {
        $this->checkKey($key);
        if (! $key->has('d')) {
            throw new InvalidKeyException('The OKP key is not private');
        }
        $d = $key->get('d');
        if (! is_string($d) || $d === '') {
            throw new InvalidKeyException('Invalid "d" parameter.');
        }
        if (OKPKey::supportsSodium(static::curve())) {
            return $this->signWithSodium($key, $d, $input);
        }

        return OKPKey::signWithOpenSSL($key, $input);
    }

    #[Override]
    public function verify(JWK $key, string $input, string $signature): bool
    {
        if ($signature === '') {
            return false;
        }
        $this->checkKey($key);
        if (strlen($signature) !== self::SIGNATURE_SIZES[static::curve()]) {
            return false;
        }
        $x = $key->get('x');
        if (! is_string($x) || $x === '') {
            throw new InvalidKeyException('Invalid "x" parameter.');
        }
        if (OKPKey::supportsSodium(static::curve())) {
            return sodium_crypto_sign_verify_detached($signature, $input, Base64UrlSafe::decodeNoPadding($x));
        }

        return OKPKey::verifyWithOpenSSL($key, $input, $signature);
    }

    /**
     * The only curve this algorithm accepts.
     */
    abstract protected static function curve(): string;

    /**
     * @param non-empty-string $d
     *
     * @return non-empty-string
     */
    private function signWithSodium(JWK $key, string $d, string $input): string
    {
        $d = Base64UrlSafe::decodeNoPadding($d);
        $x = $key->has('x') ? $key->get('x') : null;
        if ($x === null) {
            $x = SodiumEd25519::publickey_from_secretkey($d);
        } else {
            if (! is_string($x) || $x === '') {
                throw new InvalidKeyException('Invalid "x" parameter.');
            }
            $x = Base64UrlSafe::decodeNoPadding($x);
        }
        $signature = sodium_crypto_sign_detached($input, $d . $x);
        if ($signature === '') {
            throw new RuntimeException('Unable to sign the input.');
        }

        return $signature;
    }

    private function checkKey(JWK $key): void
    {
        if (! in_array($key->get('kty'), $this->allowedKeyTypes(), true)) {
            throw new InvalidKeyException('Wrong key type.');
        }
        if (! $key->has('crv')) {
            throw new InvalidKeyException('The key parameter "crv" is missing.');
        }
        if ($key->get('crv') !== static::curve()) {
            throw $this->curveMismatchException();
        }
    }

    /**
     * The exception thrown when the key is on another curve than the one the algorithm accepts. The fully-specified
     * algorithms throw an InvalidKeyException, as the key is what does not fit; the polymorphic "EdDSA" keeps the
     * UnsupportedCurveException it threw before 4.3.
     */
    protected function curveMismatchException(): InvalidArgumentException
    {
        return new InvalidKeyException(sprintf(
            'The algorithm "%s" only accepts keys on the "%s" curve.',
            $this->name(),
            static::curve()
        ));
    }
}
