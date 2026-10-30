<?php

declare(strict_types=1);

namespace Jose\Component\Signature\Algorithm;

use Jose\Component\Core\Exception\InvalidArgumentException;
use Jose\Component\Core\Exception\UnsupportedCurveException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\OKPKey;
use Override;
use function trigger_deprecation;

/**
 * The polymorphic "EdDSA" algorithm of RFC 8037 section 3.1, restricted to the Ed25519 curve as it always was in
 * this library.
 *
 * RFC 9864 section 4.1.2 deprecates the identifier in favour of the fully-specified "Ed25519" and "Ed448": the name
 * of the algorithm alone must say which curve is in use. The algorithm keeps working for the tokens already in
 * circulation, and its removal is a candidate for 5.0.0.
 *
 * @deprecated since 4.3.0, deprecated by RFC 9864. Use "Ed25519" (or "Ed448") instead; the keys are unchanged, only
 * the "alg" value differs.
 */
final readonly class EdDSA extends AbstractEdDSA
{
    #[Override]
    public function name(): string
    {
        return 'EdDSA';
    }

    /**
     * Issuing a new token with the deprecated identifier is what RFC 9864 asks to stop; verifying the tokens already
     * in circulation is not, so only signing raises the deprecation.
     */
    #[Override]
    public function sign(JWK $key, string $input): string
    {
        trigger_deprecation(
            'web-token/jwt-framework',
            '4.3.0',
            'Signing with the "EdDSA" algorithm is deprecated. Use the fully-specified "Ed25519" algorithm (%s) instead: the key is unchanged, only the "alg" value differs.',
            Ed25519::class
        );

        return parent::sign($key, $input);
    }

    #[Override]
    protected static function curve(): string
    {
        return OKPKey::CURVE_ED25519;
    }

    #[Override]
    protected function curveMismatchException(): InvalidArgumentException
    {
        return new UnsupportedCurveException('Unsupported curve.');
    }
}
