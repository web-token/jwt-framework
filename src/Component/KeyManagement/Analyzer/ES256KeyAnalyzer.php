<?php

declare(strict_types=1);

namespace Jose\Component\KeyManagement\Analyzer;

use Jose\Component\Core\Util\Ecc\Curve;
use Jose\Component\Core\Util\Ecc\NistCurve;

final class ES256KeyAnalyzer extends ESKeyAnalyzer
{
    protected function getAlgorithmName(): string
    {
        return 'ES256';
    }

    protected function getCurveName(): string
    {
        return 'P-256';
    }

    protected function getCurve(): Curve
    {
        return NistCurve::curve256();
    }

    protected function getKeySize(): int
    {
        return 256;
    }
}
