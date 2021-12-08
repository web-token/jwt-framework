<?php

declare(strict_types=1);

namespace Jose\Component\Signature\Algorithm;

final class RS256 extends RSAPKCS1
{
    public function name(): string
    {
        return 'RS256';
    }

    protected function getAlgorithm(): string
    {
        return 'sha256';
    }
}
