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

use Jose\Component\Core\JWK;
use Jose\Component\Encryption\Algorithm\KeyEncryptionAlgorithm;

interface KeyWrapping extends KeyEncryptionAlgorithm
{
    /**
     * Encrypt the CEK.
     *
     * @param \Jose\Component\Core\JWK $key              The key used to wrap the CEK
     * @param string                   $cek              The CEK to encrypt
     * @param array                    $completeHeader   The complete header of the JWT
     * @param array                    $additionalHeader The complete header of the JWT
     */
    public function wrapKey(JWK $key, string $cek, array $completeHeader, array &$additionalHeader): string;

    /**
     * Decrypt de CEK.
     *
     * @param \Jose\Component\Core\JWK $key            The key used to wrap the CEK
     * @param string                   $encrypted_cek  The CEK to decrypt
     * @param array                    $completeHeader The complete header of the JWT
     */
    public function unwrapKey(JWK $key, string $encrypted_cek, array $completeHeader): string;
}
