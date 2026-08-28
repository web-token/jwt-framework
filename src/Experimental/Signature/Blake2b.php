<?php

declare(strict_types=1);

namespace Jose\Experimental\Signature;

use InvalidArgumentException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Signature\Algorithm\MacAlgorithm;
use Jose\Component\Signature\Algorithm\SignatureAlgorithm;
use Override;
use RuntimeException;
use function extension_loaded;
use function in_array;
use function is_string;
use function strlen;
use function trigger_deprecation;

/**
 * @see \Jose\Tests\Component\Signature\Algorithm\Blake2bTest
 */
final readonly class Blake2b implements MacAlgorithm, SignatureAlgorithm
{
    private const MINIMUM_KEY_LENGTH = 32;

    public function __construct()
    {
        if (! extension_loaded('sodium')) {
            throw new RuntimeException('Please install the Sodium extension');
        }
    }

    #[Override]
    public function allowedKeyTypes(): array
    {
        return ['oct'];
    }

    #[Override]
    public function name(): string
    {
        return 'BLAKE2B';
    }

    #[Override]
    public function verify(JWK $key, string $input, string $signature): bool
    {
        return hash_equals($this->sign($key, $input), $signature);
    }

    #[Override]
    public function sign(JWK $key, string $input): string
    {
        $k = $this->getKey($key);

        return sodium_crypto_generichash($input, $k);
    }

    /**
     * @deprecated since 4.3.0, use sign() instead. Will be removed in 5.0.0.
     */
    #[Override]
    public function hash(JWK $key, string $input): string
    {
        trigger_deprecation(
            'web-token/jwt-framework',
            '4.3.0',
            'The method "%s::hash()" is deprecated and will be removed in 5.0.0. Use "%s::sign()" instead.',
            self::class,
            self::class
        );

        return $this->sign($key, $input);
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
        if (strlen($key) < self::MINIMUM_KEY_LENGTH) {
            throw new InvalidArgumentException('Key provided is shorter than 256 bits.');
        }

        return $key;
    }
}
