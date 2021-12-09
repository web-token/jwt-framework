<?php

declare(strict_types=1);

namespace Jose\Component\Signature\Algorithm;

use InvalidArgumentException;
use Jose\Component\Core\JWK;

final class HS384 extends HMAC
{
    public function name(): string
    {
        return 'HS384';
    }

    protected function getHashAlgorithm(): string
    {
        return 'sha384';
    }

    protected function getKey(JWK $key): string
    {
        $k = parent::getKey($key);
        if (mb_strlen($k, '8bit') < 48) {
            throw new InvalidArgumentException('Invalid key length.');
        }

        return $k;
    }
}
