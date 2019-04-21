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

use Assert\Assertion;
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
        Assertion::true($key->has('k'), 'The key parameter "k" is missing.');

        return Base64Url::decode($key->get('k'));
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
