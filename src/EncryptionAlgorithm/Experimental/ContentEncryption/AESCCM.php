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

use Jose\Component\Encryption\Algorithm\ContentEncryptionAlgorithm;
use RuntimeException;

abstract class AESCCM implements ContentEncryptionAlgorithm
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
        $calculated_aad = $encoded_protected_header;
        if (null !== $aad) {
            $calculated_aad .= '.'.$aad;
        }
        $tag = '';
        $result = openssl_encrypt($data, $this->getMode(), $cek, OPENSSL_RAW_DATA, $iv, $tag, $calculated_aad, $this->getTagLength());
        if (false === $result) {
            throw new RuntimeException('Unable to encrypt the content');
        }

        return $result;
    }

    /**
     * @throws RuntimeException if the data cannot be decrypted
     */
    public function decryptContent(string $data, string $cek, string $iv, ?string $aad, string $encoded_protected_header, string $tag): string
    {
        $calculated_aad = $encoded_protected_header;
        if (null !== $aad) {
            $calculated_aad .= '.'.$aad;
        }

        $result = openssl_decrypt($data, $this->getMode(), $cek, OPENSSL_RAW_DATA, $iv, $tag, $calculated_aad);
        if (false === $result) {
            throw new RuntimeException('Unable to decrypt the content');
        }

        return $result;
    }

    abstract protected function getMode(): string;

    abstract protected function getTagLength(): int;
}
