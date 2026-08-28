<?php

declare(strict_types=1);

namespace Jose\Experimental\Signature;

use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\HMAC;
use Override;

final readonly class HS256_64 extends HMAC
{
    #[Override]
    public function sign(JWK $key, string $input): string
    {
        return substr($this->computeMac($key, $input), 0, 8);
    }

    /**
     * @deprecated since 4.3.0, use sign() instead. Will be removed in 5.0.0.
     */
    #[Override]
    public function hash(JWK $key, string $input): string
    {
        $signature = parent::hash($key, $input);

        return substr($signature, 0, 8);
    }

    #[Override]
    public function name(): string
    {
        return 'HS256/64';
    }

    #[Override]
    protected function getHashAlgorithm(): string
    {
        return 'sha256';
    }
}
