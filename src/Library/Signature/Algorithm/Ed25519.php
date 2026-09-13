<?php

declare(strict_types=1);

namespace Jose\Component\Signature\Algorithm;

use Jose\Component\Core\Util\OKPKey;
use Override;

/**
 * The fully-specified "Ed25519" algorithm of RFC 9864 section 4.1.1: PureEdDSA over the Ed25519 curve, the
 * replacement of the deprecated polymorphic "EdDSA" for that curve.
 *
 * A key carrying "alg": "EdDSA" is refused by this algorithm and a key carrying "alg": "Ed25519" by "EdDSA": the
 * "alg" of a key must be the name of the algorithm using it. Keys without "alg" work with both.
 */
final readonly class Ed25519 extends AbstractEdDSA
{
    #[Override]
    public function name(): string
    {
        return 'Ed25519';
    }

    #[Override]
    protected static function curve(): string
    {
        return OKPKey::CURVE_ED25519;
    }
}
