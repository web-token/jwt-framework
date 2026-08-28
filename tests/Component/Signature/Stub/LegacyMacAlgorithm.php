<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Signature\Stub;

use InvalidArgumentException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Signature\Algorithm\MacAlgorithm;
use Override;
use function in_array;
use function is_string;

/**
 * A MAC algorithm that only implements MacAlgorithm, the way third-party algorithms did before 4.3.0 introduced
 * SignatureAlgorithm::sign() as the method to use.
 */
final readonly class LegacyMacAlgorithm implements MacAlgorithm
{
    #[Override]
    public function name(): string
    {
        return 'LEGACY-HS256';
    }

    #[Override]
    public function allowedKeyTypes(): array
    {
        return ['oct'];
    }

    #[Override]
    public function hash(JWK $key, string $input): string
    {
        return hash_hmac('sha256', $input, $this->getKey($key), true);
    }

    #[Override]
    public function verify(JWK $key, string $input, string $signature): bool
    {
        return hash_equals($this->hash($key, $input), $signature);
    }

    private function getKey(JWK $key): string
    {
        if (! in_array($key->get('kty'), $this->allowedKeyTypes(), true)) {
            throw new InvalidArgumentException('Wrong key type.');
        }
        $k = $key->get('k');
        if (! is_string($k)) {
            throw new InvalidArgumentException('The key parameter "k" is invalid.');
        }

        return Base64UrlSafe::decodeNoPadding($k);
    }
}
