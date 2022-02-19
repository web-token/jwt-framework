<?php

declare(strict_types=1);

namespace Jose\Component\KeyManagement\Analyzer;

final class ES384KeyAnalyzer extends ESKeyAnalyzer
{
    protected function getAlgorithmName(): string
    {
        return 'ES384';
    }

    protected function getCurveName(): string
    {
        return 'P-384';
    }

    protected function getKeySize(): int
    {
        return 384;
    }
}
