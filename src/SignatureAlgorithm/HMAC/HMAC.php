<?php

declare(strict_types=1);

namespace Jose\Component\Signature\Algorithm;

use function in_array;
use InvalidArgumentException;
use function is_string;
use Jose\Component\Core\JWK;
use ParagonIE\ConstantTime\Base64UrlSafe;

abstract class HMAC implements MacAlgorithm
{
    public function allowedKeyTypes(): array
    {
        return ['oct'];
    }

    public function verify(JWK $key, string $input, string $signature): bool
    {
        return hash_equals($this->hash($key, $input), $signature);
    }

    public function hash(JWK $key, string $input): string
    {
        $k = $this->getKey($key);

        return hash_hmac($this->getHashAlgorithm(), $input, $k, true);
    }

    protected function getKey(JWK $key): string
    {
        if (! in_array($key->get('kty'), $this->allowedKeyTypes(), true)) {
            throw new InvalidArgumentException('Wrong key type.');
        }
        if (! $key->has('k')) {
            throw new InvalidArgumentException('The key parameter "k" is missing.');
        }
        $k = $key->get('k');
        if (! is_string($k)) {
            throw new InvalidArgumentException('The key parameter "k" is invalid.');
        }

        return Base64UrlSafe::decode($k);
    }

    abstract protected function getHashAlgorithm(): string;
}
