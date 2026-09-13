<?php

declare(strict_types=1);

namespace Jose\Component\KeyManagement\Analyzer;

use Jose\Component\Core\Util\Ecc\Curve;
use Jose\Component\Core\Util\Ecc\KoblitzCurve;
use Override;

/**
 * Checks the keys on the secp256k1 curve used by the "ES256K" algorithm (RFC 8812).
 */
final readonly class ES256KKeyAnalyzer extends ESKeyAnalyzer
{
    #[Override]
    protected function getAlgorithmName(): string
    {
        return 'ES256K';
    }

    #[Override]
    protected function getCurveName(): string
    {
        return 'secp256k1';
    }

    #[Override]
    protected function getCurve(): Curve
    {
        return KoblitzCurve::secp256k1();
    }

    #[Override]
    protected function getKeySize(): int
    {
        return 256;
    }
}
