<?php

declare(strict_types=1);

namespace Jose\Experimental\Signature;

use Jose\Component\Signature\Algorithm\HMAC;

final class HS1 extends HMAC
{
    public function name(): string
    {
        return 'HS1';
    }

    protected function getHashAlgorithm(): string
    {
        return 'sha1';
    }
}
