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

namespace Jose\Component\Encryption\Algorithm\KeyEncryption;

use Jose\Component\Core\JWK;
use Jose\Component\Encryption\Algorithm\KeyEncryptionAlgorithmInterface;

/**
 * Interface KeyEncryptionInterface.
 */
interface KeyEncryptionInterface extends KeyEncryptionAlgorithmInterface
{
    /**
     * Encrypt the CEK.
     *
     * @param JWK    $key                The key used to wrap the CEK
     * @param string $cek                The CEK to encrypt
     * @param array  $complete_headers   The complete header of the JWT
     * @param array  $additional_headers Additional headers
     *
     * @throws \Exception If key does not support the algorithm or if the key usage does not authorize the operation
     *
     * @return string The encrypted CEK
     */
    public function encryptKey(JWK $key, string $cek, array $complete_headers, array &$additional_headers): string;

    /**
     * Decrypt de CEK.
     *
     * @param JWK    $key           The key used to wrap the CEK
     * @param string $encrypted_cek The CEK to decrypt
     * @param array  $header        The complete header of the JWT
     *
     * @throws \Exception If key does not support the algorithm or if the key usage does not authorize the operation
     *
     * @return string The decrypted CEK
     */
    public function decryptKey(JWK $key, string $encrypted_cek, array $header): string;
}
