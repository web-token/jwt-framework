<?php

declare(strict_types=1);

namespace Jose\Component\Signature\Algorithm;

use InvalidArgumentException;
use Jose\Component\Core\JWK;
use function in_array;

final class None implements SignatureAlgorithm
{
    public function allowedKeyTypes(): array
    {
        return ['none'];
    }

    public function sign(JWK $key, string $input): string
    {
        $this->checkKey($key);

        return '';
    }

    public function verify(JWK $key, string $input, string $signature): bool
    {
        return $signature === '';
    }

    public function name(): string
    {
        return 'none';
    }

    private function checkKey(JWK $key): void
    {
        if (! in_array($key->get('kty'), $this->allowedKeyTypes(), true)) {
            throw new InvalidArgumentException('Wrong key type.');
        }
    }
}
