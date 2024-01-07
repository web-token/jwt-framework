<?php

declare(strict_types=1);

namespace Jose\Experimental\Signature;

use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\HMAC;

final class HS256_64 extends HMAC
{
    public function hash(JWK $key, string $input): string
    {
        $signature = parent::hash($key, $input);

        return mb_substr($signature, 0, 8, '8bit');
    }

    public function name(): string
    {
        return 'HS256/64';
    }

    protected function getHashAlgorithm(): string
    {
        return 'sha256';
    }
}
