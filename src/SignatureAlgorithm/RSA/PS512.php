<?php

declare(strict_types=1);

namespace Jose\Component\Signature\Algorithm;

final class PS512 extends RSAPSS
{
    public function name(): string
    {
        return 'PS512';
    }

    protected function getAlgorithm(): string
    {
        return 'sha512';
    }
}
