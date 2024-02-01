<?php

declare(strict_types=1);

namespace Jose\Component\KeyManagement\Analyzer;

final class HS384KeyAnalyzer extends HSKeyAnalyzer
{
    protected function getAlgorithmName(): string
    {
        return 'HS384';
    }

    protected function getMinimumKeySize(): int
    {
        return 384;
    }
}
