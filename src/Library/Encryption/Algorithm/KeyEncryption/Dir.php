<?php

declare(strict_types=1);

namespace Jose\Component\Encryption\Algorithm\KeyEncryption;

use Jose\Component\Core\Exception\InvalidKeyException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use Override;
use function in_array;
use function is_string;

final readonly class Dir implements DirectEncryption
{
    #[Override]
    public function getCEK(JWK $key): string
    {
        if (! in_array($key->get('kty'), $this->allowedKeyTypes(), true)) {
            throw new InvalidKeyException('Wrong key type.');
        }
        if (! $key->has('k')) {
            throw new InvalidKeyException('The key parameter "k" is missing.');
        }
        $k = $key->get('k');
        if (! is_string($k)) {
            throw new InvalidKeyException('The key parameter "k" is invalid.');
        }

        return Base64UrlSafe::decodeNoPadding($k);
    }

    #[Override]
    public function name(): string
    {
        return 'dir';
    }

    #[Override]
    public function allowedKeyTypes(): array
    {
        return ['oct'];
    }

    #[Override]
    public function getKeyManagementMode(): string
    {
        return self::MODE_DIRECT;
    }
}
