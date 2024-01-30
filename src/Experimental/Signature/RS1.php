<?php

declare(strict_types=1);

namespace Jose\Experimental\Signature;

use Jose\Component\Signature\Algorithm\RSAPKCS1;

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
