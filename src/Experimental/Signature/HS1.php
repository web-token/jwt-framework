<?php

declare(strict_types=1);

namespace Jose\Experimental\Signature;

use Jose\Component\Signature\Algorithm\HMAC;
use Override;

final readonly class HS1 extends HMAC
{
    #[Override]
    public function name(): string
    {
        return 'HS1';
    }

    #[Override]
    protected function getHashAlgorithm(): string
    {
        return 'sha1';
    }
}
