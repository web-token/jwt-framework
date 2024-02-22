<?php

declare(strict_types=1);

namespace Jose\Component\Signature\Algorithm;

final class PS256 extends RSAPSS
{
    public function name(): string
    {
        return 'PS256';
    }

    protected function getAlgorithm(): string
    {
        return 'sha256';
    }
}
