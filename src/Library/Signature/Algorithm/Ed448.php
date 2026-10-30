<?php

declare(strict_types=1);

namespace Jose\Component\Signature\Algorithm;

use Jose\Component\Core\Util\OKPKey;
use Override;

/**
 * The fully-specified "Ed448" algorithm of RFC 9864 section 4.1.1: PureEdDSA over the Ed448 curve.
 *
 * ext-sodium does not know Ed448, so the algorithm runs on OpenSSL and needs PHP 8.4 or later; isSupported() tells
 * whether the platform can run it and the constructor throws when it cannot.
 */
final readonly class Ed448 extends AbstractEdDSA
{
    #[Override]
    public function name(): string
    {
        return 'Ed448';
    }

    #[Override]
    protected static function curve(): string
    {
        return OKPKey::CURVE_ED448;
    }
}
