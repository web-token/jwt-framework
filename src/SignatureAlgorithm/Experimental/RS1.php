<?php

declare(strict_types=1);

namespace Jose\Component\Signature\Algorithm;

final class RS1 extends RSAPKCS1
{
    public function name(): string
    {
        return 'RS1';
    }

    protected function getAlgorithm(): string
    {
        return 'sha1';
    }
}
