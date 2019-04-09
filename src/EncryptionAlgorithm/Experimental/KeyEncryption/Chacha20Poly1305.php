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
use Jose\Component\Core\JWK;
use function Safe\openssl_decrypt;
use function Safe\openssl_encrypt;

final class Chacha20Poly1305 implements KeyEncryption
{
    public function __construct()
    {
        Assertion::inArray('chacha20-poly1305', \openssl_get_cipher_methods(), 'The algorithm "chacha20-poly1305" is not supported in this platform.');
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
        $nonce = \random_bytes(12);

        // We set header parameters
        $additionalHeader['nonce'] = Base64Url::encode($nonce);

        $result = openssl_encrypt($cek, 'chacha20-poly1305', $k, OPENSSL_RAW_DATA, $nonce);

        return $result;
    }

    public function decryptKey(JWK $key, string $encrypted_cek, array $header): string
    {
        $k = $this->getKey($key);
        $this->checkHeaderAdditionalParameters($header);
        $nonce = Base64Url::decode($header['nonce']);

        $result = openssl_decrypt($encrypted_cek, 'chacha20-poly1305', $k, OPENSSL_RAW_DATA, $nonce);

        return $result;
    }

    public function getKeyManagementMode(): string
    {
        return self::MODE_ENCRYPT;
    }

    private function getKey(JWK $key): string
    {
        Assertion::inArray($key->get('kty'), $this->allowedKeyTypes(), 'Wrong key type.');
        Assertion::true($key->has('k'), 'The key parameter "k" is missing.');
        $k = $key->get('k');
        Assertion::string($k, 'The key parameter "k" is invalid.');

        return Base64Url::decode($k);
    }

    private function checkHeaderAdditionalParameters(array $header): void
    {
        Assertion::keyExists($header, 'nonce', 'The header parameter "nonce" is missing.');
        Assertion::string($header['nonce'], 'The header parameter "nonce" is not valid.');
    }
}
