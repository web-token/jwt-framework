<?php

declare(strict_types=1);

namespace Jose\Component\KeyManagement\Analyzer;

final class ES512KeyAnalyzer extends ESKeyAnalyzer
{
    protected function getAlgorithmName(): string
    {
        return 'ES512';
    }

    protected function getCurveName(): string
    {
        return 'P-521';
    }

    protected function getKeySize(): int
    {
        return 512; //528
    }
}
