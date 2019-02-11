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

namespace Jose\Component\Encryption\Algorithm\ContentEncryption;

use Assert\Assertion;
use Base64Url\Base64Url;
use Jose\Component\Encryption\Algorithm\ContentEncryptionAlgorithm;

abstract class AESGCM implements ContentEncryptionAlgorithm
{
    public function allowedKeyTypes(): array
    {
        return []; //Irrelevant
    }

    public function encryptContent(string $data, string $cek, string $iv, ?string $aad, string $encoded_protected_header, ?string &$tag = null): string
    {
        $calculated_aad = $encoded_protected_header;
        if (null !== $aad) {
            $calculated_aad .= '.'.Base64Url::encode($aad);
        }
        $tag = '';
        $result = \openssl_encrypt($data, $this->getMode(), $cek, OPENSSL_RAW_DATA, $iv, $tag, $calculated_aad);
        Assertion::false(false === $result, 'Unable to encrypt.');

        return $result;
    }

    public function decryptContent(string $data, string $cek, string $iv, ?string $aad, string $encoded_protected_header, string $tag): string
    {
        $calculated_aad = $encoded_protected_header;
        if (null !== $aad) {
            $calculated_aad .= '.'.Base64Url::encode($aad);
        }

        $result = \openssl_decrypt($data, $this->getMode(), $cek, OPENSSL_RAW_DATA, $iv, $tag, $calculated_aad);
        Assertion::false(false === $result, 'Unable to decrypt or to verify the tag.');

        return $result;
    }

    public function getIVSize(): int
    {
        return 96;
    }

    abstract protected function getMode(): string;
}
