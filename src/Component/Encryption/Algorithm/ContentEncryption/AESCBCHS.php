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

namespace Jose\Component\Encryption\Algorithm\ContentEncryption;

use Jose\Component\Encryption\Algorithm\ContentEncryptionAlgorithm;

/**
 * Class AESCBCHS.
 */
abstract class AESCBCHS implements ContentEncryptionAlgorithm
{
    /**
     * {@inheritdoc}
     */
    public function allowedKeyTypes(): array
    {
        return []; //Irrelevant
    }

    /**
     * {@inheritdoc}
     */
    public function encryptContent(string $data, string $cek, string $iv, ?string $aad, string $encoded_protected_header, ?string &$tag): string
    {
        $k = mb_substr($cek, $this->getCEKSize() / 16, null, '8bit');
        $cyphertext = openssl_encrypt($data, $this->getMode(), $k, OPENSSL_RAW_DATA, $iv);
        if (false === $cyphertext) {
            throw new \RuntimeException('Unable to encrypt.');
        }

        $tag = $this->calculateAuthenticationTag($cyphertext, $cek, $iv, $aad, $encoded_protected_header);

        return $cyphertext;
    }

    /**
     * @param string      $data
     * @param string      $cek
     * @param string      $iv
     * @param string      $encoded_protected_header
     * @param string|null $aad
     * @param string      $tag
     *
     * @return string
     */
    public function decryptContent(string $data, string $cek, string $iv, ?string $aad, string $encoded_protected_header, string $tag): string
    {
        if (!$this->isTagValid($data, $cek, $iv, $aad, $encoded_protected_header, $tag)) {
            throw new \InvalidArgumentException('Unable to verify the tag.');
        }
        $k = mb_substr($cek, $this->getCEKSize() / 16, null, '8bit');

        $plaintext = openssl_decrypt($data, $this->getMode(), $k, OPENSSL_RAW_DATA, $iv);
        if (false === $plaintext) {
            throw new \RuntimeException('Unable to decrypt.');
        }

        return $plaintext;
    }

    /**
     * @param string      $encrypted_data
     * @param string      $cek
     * @param string      $iv
     * @param null|string $aad
     * @param string      $encoded_header
     *
     * @return string
     */
    protected function calculateAuthenticationTag(string $encrypted_data, string $cek, string $iv, ?string $aad, string $encoded_header): string
    {
        $calculated_aad = $encoded_header;
        if (null !== $aad) {
            $calculated_aad .= '.'.$aad;
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

    /**
     * @param string      $authentication_tag
     * @param string      $encoded_header
     * @param string      $encrypted_data
     * @param string      $cek
     * @param string      $iv
     * @param string|null $aad
     *
     * @return bool
     */
    protected function isTagValid(string $encrypted_data, string $cek, string $iv, ?string $aad, string $encoded_header, string $authentication_tag): bool
    {
        return hash_equals($authentication_tag, $this->calculateAuthenticationTag($encrypted_data, $cek, $iv, $aad, $encoded_header));
    }

    /**
     * @return string
     */
    abstract protected function getHashAlgorithm(): string;

    /**
     * @return string
     */
    abstract protected function getMode(): string;

    /**
     * @return int
     */
    public function getIVSize(): int
    {
        return 128;
    }
}
