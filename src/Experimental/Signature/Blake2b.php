<?php

declare(strict_types=1);

namespace Jose\Experimental\Signature;

use InvalidArgumentException;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\MacAlgorithm;
use ParagonIE\ConstantTime\Base64UrlSafe;
use RuntimeException;
use function extension_loaded;
use function in_array;
use function is_string;

/**
 * @see \Jose\Tests\Component\Signature\Algorithm\Blake2bTest
 */
final class Blake2b implements MacAlgorithm
{
    private const MINIMUM_KEY_LENGTH = 32;

    public function __construct()
    {
        if (! extension_loaded('sodium')) {
            throw new RuntimeException('Please install the Sodium extension');
        }
    }

    public function allowedKeyTypes(): array
    {
        return ['oct'];
    }

    public function name(): string
    {
        return 'BLAKE2B';
    }

    public function verify(JWK $key, string $input, string $signature): bool
    {
        return hash_equals($this->hash($key, $input), $signature);
    }

    public function hash(JWK $key, string $input): string
    {
        $k = $this->getKey($key);

        return sodium_crypto_generichash($input, $k);
    }

    private function getKey(JWK $key): string
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
        $key = Base64UrlSafe::decodeNoPadding($k);
        if (mb_strlen($key, '8bit') < self::MINIMUM_KEY_LENGTH) {
            throw new InvalidArgumentException('Key provided is shorter than 256 bits.');
        }

        return $key;
    }
}
