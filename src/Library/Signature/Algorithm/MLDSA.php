<?php

declare(strict_types=1);

namespace Jose\Component\Signature\Algorithm;

use Jose\Component\Core\Exception\InvalidKeyException;
use Jose\Component\Core\Exception\MissingDependencyException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\AKPKey;
use Override;
use function sprintf;
use function strlen;

/**
 * ML-DSA (FIPS 204), as RFC 9964 registers it for JOSE: the pure signature of FIPS 204 algorithm 2, with the empty
 * context string, over a key of the AKP type. No HashML-DSA (section 7.2 of the RFC explains why it is excluded), no
 * non-empty "ctx" (section 5: "The ctx parameter MUST be the empty string").
 *
 * The computation is OpenSSL's and needs PHP 8.4 and an OpenSSL runtime that provides ML-DSA (3.5 or later), see
 * AKPKey: isSupported() tells whether the platform can run the algorithm, the constructor throws a
 * MissingDependencyException naming the missing piece when it cannot, and the Symfony Bundle registers the algorithm
 * only when it can run.
 *
 * The key is checked before OpenSSL sees it (RFC 9964 section 7.3): the "alg" the AKP type cannot do without, the
 * sizes of the parameter set, and - when the key carries both halves - that "pub" is what the seed expands to
 * (section 7.4). A signature of the wrong length is rejected before any backend is called, so that a malformed or
 * tampered signature is "false", never an exception.
 */
abstract readonly class MLDSA implements SignatureAlgorithm
{
    public function __construct()
    {
        if (! static::isSupported()) {
            throw new MissingDependencyException(sprintf(
                'The algorithm "%s" requires %s.',
                $this->name(),
                AKPKey::missingDependency()
            ));
        }
    }

    /**
     * Tells whether the platform can run ML-DSA: PHP 8.4 or later, and an OpenSSL runtime that provides it. The
     * OpenSSL check is a runtime probe kept for the process, because OPENSSL_VERSION_TEXT reports the headers PHP was
     * built against, not the library it loaded.
     */
    public static function isSupported(): bool
    {
        return AKPKey::supportsOpenSSL();
    }

    #[Override]
    public function allowedKeyTypes(): array
    {
        return [AKPKey::KEY_TYPE];
    }

    /**
     * @return non-empty-string
     */
    #[Override]
    public function sign(JWK $key, string $input): string
    {
        AKPKey::checkKey($key, $this->name());
        if (! $key->has('priv')) {
            throw new InvalidKeyException('The AKP key is not private');
        }

        return AKPKey::sign($key, $input);
    }

    #[Override]
    public function verify(JWK $key, string $input, string $signature): bool
    {
        if ($signature === '') {
            return false;
        }
        AKPKey::checkKey($key, $this->name());
        if (strlen($signature) !== AKPKey::SIGNATURE_LENGTHS[$this->name()]) {
            return false;
        }

        return AKPKey::verify($key->toPublic(), $input, $signature);
    }
}
