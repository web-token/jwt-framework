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
use Exception;
use function in_array;
use InvalidArgumentException;
use function is_string;
use Jose\Component\Core\JWK;
use RuntimeException;

abstract class AESGCMKW implements KeyWrapping
{
    public function allowedKeyTypes(): array
    {
        return ['oct'];
    }

    /**
     * @throws RuntimeException if the CEK cannot be encrypted
     * @throws Exception        if the random bytes cannot be generated
     */
    public function wrapKey(JWK $key, string $cek, array $completeHeader, array &$additionalHeader): string
    {
        $kek = $this->getKey($key);
        $iv = random_bytes(96 / 8);
        $additionalHeader['iv'] = Base64Url::encode($iv);

        $mode = sprintf('aes-%d-gcm', $this->getKeySize());
        $tag = '';
        $encrypted_cek = openssl_encrypt($cek, $mode, $kek, OPENSSL_RAW_DATA, $iv, $tag, '');
        if (false === $encrypted_cek) {
            throw new RuntimeException('Unable to encrypt the CEK');
        }
        $additionalHeader['tag'] = Base64Url::encode($tag);

        return $encrypted_cek;
    }

    /**
     * @throws RuntimeException if the CEK cannot be decrypted
     */
    public function unwrapKey(JWK $key, string $encrypted_cek, array $completeHeader): string
    {
        $kek = $this->getKey($key);
        $this->checkAdditionalParameters($completeHeader);

        $tag = Base64Url::decode($completeHeader['tag']);
        $iv = Base64Url::decode($completeHeader['iv']);

        $mode = sprintf('aes-%d-gcm', $this->getKeySize());
        $cek = openssl_decrypt($encrypted_cek, $mode, $kek, OPENSSL_RAW_DATA, $iv, $tag, '');
        if (false === $cek) {
            throw new RuntimeException('Unable to decrypt the CEK');
        }

        return $cek;
    }

    public function getKeyManagementMode(): string
    {
        return self::MODE_WRAP;
    }

    /**
     * @throws InvalidArgumentException if the key is invalid
     */
    protected function getKey(JWK $key): string
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
     * @throws InvalidArgumentException if the header parameter iv or tag is missing
     */
    protected function checkAdditionalParameters(array $header): void
    {
        foreach (['iv', 'tag'] as $k) {
            if (!isset($header[$k])) {
                throw new InvalidArgumentException(sprintf('Parameter "%s" is missing.', $k));
            }
        }
    }

    abstract protected function getKeySize(): int;
}
