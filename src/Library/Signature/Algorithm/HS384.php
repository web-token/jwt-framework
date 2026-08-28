<?php

declare(strict_types=1);

namespace Jose\Component\Signature\Algorithm;

use Jose\Component\Core\Exception\InvalidKeyException;
use Jose\Component\Core\JWK;
use Override;
use function strlen;

final readonly class HS384 extends HMAC
{
    #[Override]
    public function name(): string
    {
        return 'HS384';
    }

    #[Override]
    protected function getHashAlgorithm(): string
    {
        return 'sha384';
    }

    #[Override]
    protected function getKey(JWK $key): string
    {
        $k = parent::getKey($key);
        if (strlen($k) < 48) {
            throw new InvalidKeyException('Invalid key length.');
        }

        return $k;
    }
}
