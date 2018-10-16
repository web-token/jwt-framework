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

abstract class AESCTR implements KeyEncryption
{
    public function allowedKeyTypes(): array
    {
        return ['oct'];
    }

    public function encryptKey(JWK $key, string $cek, array $completeHeader, array &$additionalHeader): string
    {
        $this->checkKey($key);
        $iv = \random_bytes(16);
        $k = Base64Url::decode($key->get('k'));

        // We set header parameters
        $additionalHeader['iv'] = Base64Url::encode($iv);

        return \openssl_encrypt($cek, $this->getMode(), $k, OPENSSL_RAW_DATA, $iv);
    }

    public function decryptKey(JWK $key, string $encrypted_cek, array $header): string
    {
        $this->checkKey($key);
        $this->checkHeaderAdditionalParameters($header);
        $k = Base64Url::decode($key->get('k'));
        $iv = Base64Url::decode($header['iv']);

        return \openssl_decrypt($encrypted_cek, $this->getMode(), $k, OPENSSL_RAW_DATA, $iv);
    }

    public function getKeyManagementMode(): string
    {
        return self::MODE_ENCRYPT;
    }

    private function checkKey(JWK $key)
    {
        if (!\in_array($key->get('kty'), $this->allowedKeyTypes(), true)) {
            throw new \InvalidArgumentException('Wrong key type.');
        }
        if (!$key->has('k')) {
            throw new \InvalidArgumentException('The key parameter "k" is missing.');
        }
    }

    private function checkHeaderAdditionalParameters(array $header)
    {
        foreach (['iv'] as $k) {
            if (!\array_key_exists($k, $header)) {
                throw new \InvalidArgumentException(\sprintf('The header parameter "%s" is missing.', $k));
            }
            if (empty($header[$k])) {
                throw new \InvalidArgumentException(\sprintf('The header parameter "%s" is not valid.', $k));
            }
        }
    }

    abstract protected function getMode(): string;
}
