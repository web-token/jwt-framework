<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Encryption\Algorithm\KeyEncryption;

use Base64Url\Base64Url;
use function in_array;
use InvalidArgumentException;
use function is_string;
use Jose\Component\Core\JWK;
use RuntimeException;

abstract class AESCTR implements KeyEncryption
{
    public function allowedKeyTypes(): array
    {
        return ['oct'];
    }

    /**
     * @throws RuntimeException if the CEK cannot be encrypted
     */
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

    /**
     * @throws RuntimeException if the CEK cannot be decrypted
     */
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

    /**
     * @throws InvalidArgumentException if the key is invalid
     */
    private function getKey(JWK $key): string
    {
        if (!in_array($key->get('kty'), $this->allowedKeyTypes(), true)) {
            throw new InvalidArgumentException('Wrong key type.');
        }
        if (!$key->has('k')) {
            throw new InvalidArgumentException('The key parameter "k" is missing.');
        }
        $k = $key->get('k');
        if (!is_string($k)) {
            throw new InvalidArgumentException('The key parameter "k" is invalid.');
        }

        return Base64Url::decode($k);
    }

    /**
     * @throws InvalidArgumentException if the IV is missing or invalid
     */
    private function checkHeaderAdditionalParameters(array $header): void
    {
        if (!isset($header['iv'])) {
            throw new InvalidArgumentException('The header parameter "iv" is missing.');
        }
        if (!is_string($header['iv'])) {
            throw new InvalidArgumentException('The header parameter "iv" is not valid.');
        }
    }
}
