<?php

declare(strict_types=1);

namespace Jose\Component\KeyManagement\Analyzer;

final class HS512KeyAnalyzer extends HSKeyAnalyzer
{
    protected function getAlgorithmName(): string
    {
        return 'HS512';
    }

    protected function getMinimumKeySize(): int
    {
        return 512;
    }
}
