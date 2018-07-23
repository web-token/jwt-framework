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

interface KeyAgreement extends KeyEncryptionAlgorithm
{
    /**
     * Computes the agreement key.
     *
     * @param int    $encryption_key_length    Size of the key expected for the algorithm used for data encryption
     * @param string $algorithm                The algorithm
     * @param JWK    $recipient_key            The recipient key. If the key is public, then an ephemeral private key will be created, else will try to find the ephemeral key in the header
     * @param array  $complete_header          The complete header of the JWT
     * @param array  $additional_header_values Set additional header values if needed
     */
    public function getAgreementKey(int $encryption_key_length, string $algorithm, JWK $recipient_key, array $complete_header = [], array &$additional_header_values = []): string;
}
