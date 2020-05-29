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

namespace Jose\Component\Encryption\Algorithm\ContentEncryption;

use Base64Url\Base64Url;
use Jose\Component\Encryption\Algorithm\ContentEncryptionAlgorithm;
use RuntimeException;

abstract class AESCBCHS implements ContentEncryptionAlgorithm
{
    public function allowedKeyTypes(): array
    {
        return []; //Irrelevant
    }

    /**
     * @throws RuntimeException if the data cannot be encrypted
     */
    public function encryptContent(string $data, string $cek, string $iv, ?string $aad, string $encoded_protected_header, ?string &$tag = null): string
    {
        $k = mb_substr($cek, $this->getCEKSize() / 16, null, '8bit');
        $result = openssl_encrypt($data, $this->getMode(), $k, OPENSSL_RAW_DATA, $iv);
        if (false === $result) {
            throw new RuntimeException('Unable to encrypt the content');
        }

        $tag = $this->calculateAuthenticationTag($result, $cek, $iv, $aad, $encoded_protected_header);

        return $result;
    }

    /**
     * @throws RuntimeException if the data cannot be decrypted
     */
    public function decryptContent(string $data, string $cek, string $iv, ?string $aad, string $encoded_protected_header, string $tag): string
    {
        if (!$this->isTagValid($data, $cek, $iv, $aad, $encoded_protected_header, $tag)) {
            throw new RuntimeException('Unable to decrypt or to verify the tag.');
        }
        $k = mb_substr($cek, $this->getCEKSize() / 16, null, '8bit');

        $result = openssl_decrypt($data, $this->getMode(), $k, OPENSSL_RAW_DATA, $iv);
        if (false === $result) {
            throw new RuntimeException('Unable to decrypt or to verify the tag.');
        }

        return $result;
    }

    public function getIVSize(): int
    {
        return 128;
    }

    protected function calculateAuthenticationTag(string $encrypted_data, string $cek, string $iv, ?string $aad, string $encoded_header): string
    {
        $calculated_aad = $encoded_header;
        if (null !== $aad) {
            $calculated_aad .= '.'.Base64Url::encode($aad);
        }
        $mac_key = mb_substr($cek, 0, $this->getCEKSize() / 16, '8bit');
        $auth_data_length = mb_strlen($encoded_header, '8bit');

        $secured_input = implode('', [
            $calculated_aad,
            $iv,
            $encrypted_data,
            pack('N2', ($auth_data_length / 2147483647) * 8, ($auth_data_length % 2147483647) * 8),
        ]);
        $hash = hash_hmac($this->getHashAlgorithm(), $secured_input, $mac_key, true);

        return  mb_substr($hash, 0, mb_strlen($hash, '8bit') / 2, '8bit');
    }

    protected function isTagValid(string $encrypted_data, string $cek, string $iv, ?string $aad, string $encoded_header, string $authentication_tag): bool
    {
        return hash_equals($authentication_tag, $this->calculateAuthenticationTag($encrypted_data, $cek, $iv, $aad, $encoded_header));
    }

    abstract protected function getHashAlgorithm(): string;

    abstract protected function getMode(): string;
}
