<?php

declare(strict_types=1);

namespace Jose\Component\KeyManagement\Analyzer;

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

    protected function getKeySize(): int
    {
        return 256;
    }
}
