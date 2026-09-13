<?php

declare(strict_types=1);

namespace Jose\Component\Signature\Algorithm;

use Jose\Component\Core\Util\AKPKey;
use Override;

/**
 * The "ML-DSA-65" algorithm of RFC 9964 section 5: ML-DSA-65 of FIPS 204, over an AKP key.
 */
final readonly class MLDSA65 extends MLDSA
{
    #[Override]
    public function name(): string
    {
        return AKPKey::ML_DSA_65;
    }
}
