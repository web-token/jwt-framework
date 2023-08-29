<?php

declare(strict_types=1);

namespace Jose\Component\Signature\Algorithm;

final class RS512 extends RSAPKCS1
{
    public function name(): string
    {
        return 'RS512';
    }

    protected function getAlgorithm(): string
    {
        return 'sha512';
    }
}
