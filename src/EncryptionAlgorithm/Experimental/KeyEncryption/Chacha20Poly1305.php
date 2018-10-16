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

final class Chacha20Poly1305 implements KeyEncryption
{
    public function __construct()
    {
        if (!\in_array('chacha20-poly1305', \openssl_get_cipher_methods(), true)) {
            throw new \RuntimeException('The algorithm "chacha20-poly1305" is not supported in this platform.');
        }
    }

    public function allowedKeyTypes(): array
    {
        return ['oct'];
    }

    public function name(): string
    {
        return 'chacha20-poly1305';
    }

    public function encryptKey(JWK $key, string $cek, array $completeHeader, array &$additionalHeader): string
    {
        $this->checkKey($key);
        $nonce = \random_bytes(12);
        $k = Base64Url::decode($key->get('k'));

        // We set header parameters
        $additionalHeader['nonce'] = Base64Url::encode($nonce);

        return \openssl_encrypt($cek, 'chacha20-poly1305', $k, OPENSSL_RAW_DATA, $nonce);
    }

    public function decryptKey(JWK $key, string $encrypted_cek, array $header): string
    {
        $this->checkKey($key);
        $this->checkHeaderAdditionalParameters($header);
        $k = Base64Url::decode($key->get('k'));
        $nonce = Base64Url::decode($header['nonce']);

        return \openssl_decrypt($encrypted_cek, 'chacha20-poly1305', $k, OPENSSL_RAW_DATA, $nonce);
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
        foreach (['nonce'] as $k) {
            if (!\array_key_exists($k, $header)) {
                throw new \InvalidArgumentException(\sprintf('The header parameter "%s" is missing.', $k));
            }
            if (empty($header[$k])) {
                throw new \InvalidArgumentException(\sprintf('The header parameter "%s" is not valid.', $k));
            }
        }
    }
}
