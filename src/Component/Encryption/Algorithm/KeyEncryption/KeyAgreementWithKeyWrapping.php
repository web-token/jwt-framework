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

namespace Jose\Component\Encryption\Algorithm\KeyEncryption;

use Jose\Component\Core\JWK;
use Jose\Component\Encryption\Algorithm\KeyEncryptionAlgorithm;

interface KeyAgreementWithKeyWrapping extends KeyEncryptionAlgorithm
{
    /**
     * Compute and wrap the agreement key.
     *
     * @param JWK    $receiver_key             The receiver's key
     * @param string $cek                      The CEK to wrap
     * @param int    $encryption_key_length    Size of the key expected for the algorithm used for data encryption
     * @param array  $complete_header          The complete header of the JWT
     * @param array  $additional_header_values Set additional header values if needed
     *
     * @throws \Exception If key does not support the algorithm or if the key usage does not authorize the operation
     */
    public function wrapAgreementKey(JWK $receiver_key, string $cek, int $encryption_key_length, array $complete_header, array &$additional_header_values): string;

    /**
     * Unwrap and compute the agreement key.
     *
     * @param JWK    $receiver_key          The receiver's key
     * @param string $encrypted_cek         The encrypted CEK
     * @param int    $encryption_key_length Size of the key expected for the algorithm used for data encryption
     * @param array  $complete_header       The complete header of the JWT
     *
     * @throws \Exception If key does not support the algorithm or if the key usage does not authorize the operation
     *
     * @return string The decrypted CEK
     */
    public function unwrapAgreementKey(JWK $receiver_key, string $encrypted_cek, int $encryption_key_length, array $complete_header): string;
}
