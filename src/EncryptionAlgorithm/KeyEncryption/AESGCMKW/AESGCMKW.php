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

abstract class AESGCMKW implements KeyWrapping
{
    public function allowedKeyTypes(): array
    {
        return ['oct'];
    }

    public function wrapKey(JWK $key, string $cek, array $completeHeader, array &$additionalHeader): string
    {
        $this->checkKey($key);
        $kek = Base64Url::decode($key->get('k'));
        $iv = \random_bytes(96 / 8);
        $additionalHeader['iv'] = Base64Url::encode($iv);

        $mode = \sprintf('aes-%d-gcm', $this->getKeySize());
        $tag = null;
        $encrypted_cek = \openssl_encrypt($cek, $mode, $kek, OPENSSL_RAW_DATA, $iv, $tag, '');
        if (false === $encrypted_cek) {
            throw new \RuntimeException('Unable to encrypt the data.');
        }
        $additionalHeader['tag'] = Base64Url::encode($tag);

        return $encrypted_cek;
    }

    public function unwrapKey(JWK $key, string $encrypted_cek, array $completeHeader): string
    {
        $this->checkKey($key);
        $this->checkAdditionalParameters($completeHeader);

        $kek = Base64Url::decode($key->get('k'));
        $tag = Base64Url::decode($completeHeader['tag']);
        $iv = Base64Url::decode($completeHeader['iv']);

        $mode = \sprintf('aes-%d-gcm', $this->getKeySize());
        $cek = \openssl_decrypt($encrypted_cek, $mode, $kek, OPENSSL_RAW_DATA, $iv, $tag, '');
        if (false === $cek) {
            throw new \RuntimeException('Unable to decrypt or to verify the tag.');
        }

        return $cek;
    }

    public function getKeyManagementMode(): string
    {
        return self::MODE_WRAP;
    }

    protected function checkKey(JWK $key)
    {
        if (!\in_array($key->get('kty'), $this->allowedKeyTypes(), true)) {
            throw new \InvalidArgumentException('Wrong key type.');
        }
        if (!$key->has('k')) {
            throw new \InvalidArgumentException('The key parameter "k" is missing.');
        }
    }

    protected function checkAdditionalParameters(array $header)
    {
        foreach (['iv', 'tag'] as $k) {
            if (!\array_key_exists($k, $header)) {
                throw new \InvalidArgumentException(\sprintf('Parameter "%s" is missing.', $k));
            }
        }
    }

    abstract protected function getKeySize(): int;
}
