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
use RuntimeException;

abstract class AESCTR implements KeyEncryption
{
    public function allowedKeyTypes(): array
    {
        return ['oct'];
    }

    public function encryptKey(JWK $key, string $cek, array $completeHeader, array &$additionalHeader): string
    {
        $k = $this->getKey($key);
        $iv = random_bytes(16);

        // We set header parameters
        $additionalHeader['iv'] = Base64Url::encode($iv);

        $result = openssl_encrypt($cek, $this->getMode(), $k, OPENSSL_RAW_DATA, $iv);
        if (false === $result) {
            throw new RuntimeException('Unable to encrypt the CEK');
        }

        return $result;
    }

    public function decryptKey(JWK $key, string $encrypted_cek, array $header): string
    {
        $k = $this->getKey($key);
        $this->checkHeaderAdditionalParameters($header);
        $iv = Base64Url::decode($header['iv']);

        $result = openssl_decrypt($encrypted_cek, $this->getMode(), $k, OPENSSL_RAW_DATA, $iv);
        if (false === $result) {
            throw new RuntimeException('Unable to decrypt the CEK');
        }

        return $result;
    }

    public function getKeyManagementMode(): string
    {
        return self::MODE_ENCRYPT;
    }

    abstract protected function getMode(): string;

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
        Assertion::keyExists($header, 'iv', 'The header parameter "iv" is missing.');
        Assertion::string($header['iv'], 'The header parameter "iv" is not valid.');
    }
}
