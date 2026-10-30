<?php

declare(strict_types=1);

namespace Jose\Component\Signature\Algorithm;

use Jose\Component\Core\Util\AKPKey;
use Override;

/**
 * The "ML-DSA-44" algorithm of RFC 9964 section 5: ML-DSA-44 of FIPS 204, over an AKP key.
 */
final readonly class MLDSA44 extends MLDSA
{
    #[Override]
    public function name(): string
    {
        return AKPKey::ML_DSA_44;
    }
}
