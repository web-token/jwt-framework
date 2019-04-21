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
use LogicException;
use RuntimeException;

final class Chacha20Poly1305 implements KeyEncryption
{
    public function __construct()
    {
        if (!\in_array('chacha20-poly1305', openssl_get_cipher_methods(), true)) {
            throw new LogicException('The algorithm "chacha20-poly1305" is not supported in this platform.');
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
        $k = $this->getKey($key);
        $nonce = random_bytes(12);

        // We set header parameters
        $additionalHeader['nonce'] = Base64Url::encode($nonce);

        $result = openssl_encrypt($cek, 'chacha20-poly1305', $k, OPENSSL_RAW_DATA, $nonce);
        if (false === $result) {
            throw new RuntimeException('Unable to encrypt the CEK');
        }

        return $result;
    }

    public function decryptKey(JWK $key, string $encrypted_cek, array $header): string
    {
        $k = $this->getKey($key);
        $this->checkHeaderAdditionalParameters($header);
        $nonce = Base64Url::decode($header['nonce']);

        $result = openssl_decrypt($encrypted_cek, 'chacha20-poly1305', $k, OPENSSL_RAW_DATA, $nonce);
        if (false === $result) {
            throw new RuntimeException('Unable to decrypt the CEK');
        }

        return $result;
    }

    public function getKeyManagementMode(): string
    {
        return self::MODE_ENCRYPT;
    }

    private function getKey(JWK $key): string
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

    private function checkHeaderAdditionalParameters(array $header): void
    {
        if (!isset($header['nonce'])) {
            throw new InvalidArgumentException('The header parameter "nonce" is missing.');
        }
        if (!\is_string($header['nonce'])) {
            throw new InvalidArgumentException('The header parameter "nonce" is not valid.');
        }
    }
}
