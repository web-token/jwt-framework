<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Encryption\Algorithm\ContentEncryption;

use Jose\Component\Encryption\Algorithm\ContentEncryptionAlgorithmInterface;

/**
 * Class AESGCM.
 */
abstract class AESGCM implements ContentEncryptionAlgorithmInterface
{
    /**
     * {@inheritdoc}
     */
    public function allowedKeyTypes(): array
    {
        return ['oct'];
    }

    /**
     * {@inheritdoc}
     */
    public function encryptContent(string $data, string $cek, string $iv, ?string $aad, string $encoded_protected_header, ?string &$tag): string
    {
        $calculated_aad = $encoded_protected_header;
        if (null !== $aad) {
            $calculated_aad .= '.'.$aad;
        }

        $mode = sprintf('aes-%d-gcm', $this->getKeySize());
        $C = openssl_encrypt($data, $mode, $cek, OPENSSL_RAW_DATA, $iv, $tag, $calculated_aad);
        if (false === $C) {
            throw new \InvalidArgumentException('Unable to encrypt the data.');
        }

        return $C;
    }

    /**
     *  {@inheritdoc}
     */
    public function decryptContent(string $data, string $cek, string $iv, ?string $aad, string $encoded_protected_header, string $tag): string
    {
        $calculated_aad = $encoded_protected_header;
        if (null !== $aad) {
            $calculated_aad .= '.'.$aad;
        }

        $mode = sprintf('aes-%d-gcm', $this->getKeySize());
        $P = openssl_decrypt($data, $mode, $cek, OPENSSL_RAW_DATA, $iv, $tag, $calculated_aad);
        if (false === $P) {
            throw new \InvalidArgumentException('Unable to decrypt or to verify the tag.');
        }

        return $P;
    }

    /**
     * @return int
     */
    public function getIVSize(): int
    {
        return 96;
    }

    /**
     * @return int
     */
    public function getCEKSize(): int
    {
        return $this->getKeySize();
    }

    /**
     * @return int
     */
    abstract protected function getKeySize(): int;
}
