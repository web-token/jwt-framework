<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2019 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Encryption\Algorithm\KeyEncryption;

use Base64Url\Base64Url;
use InvalidArgumentException;
use Jose\Component\Core\JWK;

final class Dir implements DirectEncryption
{
    public function getCEK(JWK $key): string
    {
        if (!\in_array($key->get('kty'), $this->allowedKeyTypes(), true)) {
            throw new InvalidArgumentException('Wrong key type.');
        }
        if (!$key->has('k')) {
            throw new InvalidArgumentException('The key parameter "k" is missing.');
        }
        $k = $key->get('k');
        if (!\is_string($k)) {
            throw new InvalidArgumentException('The key parameter "k" is invalid.');
        }

        return Base64Url::decode($k);
    }

    public function name(): string
    {
        return 'dir';
    }

    public function allowedKeyTypes(): array
    {
        return ['oct'];
    }

    public function getKeyManagementMode(): string
    {
        return self::MODE_DIRECT;
    }
}
