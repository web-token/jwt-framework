<?php

declare(strict_types=1);

namespace Jose\Experimental\Signature;

use Jose\Component\Signature\Algorithm\RSAPKCS1;
use Override;

final readonly class RS1 extends RSAPKCS1
{
    #[Override]
    public function name(): string
    {
        return 'RS1';
    }

    #[Override]
    protected function getAlgorithm(): string
    {
        return 'sha1';
    }
}
