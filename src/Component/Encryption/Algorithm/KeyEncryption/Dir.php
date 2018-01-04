<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Encryption\Algorithm\KeyEncryption;

use Base64Url\Base64Url;
use Jose\Component\Core\JWK;

/**
 * Class Dir.
 */
final class Dir implements DirectEncryption
{
    /**
     * {@inheritdoc}
     */
    public function getCEK(JWK $key): string
    {
        if ('oct' !== $key->get('kty')) {
            throw new \InvalidArgumentException('Wrong key type.');
        }
        if (!$key->has('k')) {
            throw new \InvalidArgumentException('The key parameter "k" is missing.');
        }

        return Base64Url::decode($key->get('k'));
    }

    /**
     * {@inheritdoc}
     */
    public function name(): string
    {
        return 'dir';
    }

    /**
     * {@inheritdoc}
     */
    public function allowedKeyTypes(): array
    {
        return ['oct'];
    }

    /**
     * {@inheritdoc}
     */
    public function getKeyManagementMode(): string
    {
        return self::MODE_DIRECT;
    }
}
