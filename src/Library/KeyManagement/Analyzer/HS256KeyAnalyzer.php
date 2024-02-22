<?php

declare(strict_types=1);

namespace Jose\Component\KeyManagement\Analyzer;

final class HS256KeyAnalyzer extends HSKeyAnalyzer
{
    protected function getAlgorithmName(): string
    {
        return 'HS256';
    }

    protected function getMinimumKeySize(): int
    {
        return 256;
    }
}
