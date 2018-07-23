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

namespace Jose\Component\Signature\Algorithm;

use Jose\Component\Core\Algorithm;
use Jose\Component\Core\JWK;

interface SignatureAlgorithm extends Algorithm
{
    /**
     * Sign the input.
     *
     * @param JWK    $key   The private key used to sign the data
     * @param string $input The input
     *
     * @throws \Exception If key does not support the algorithm or if the key usage does not authorize the operation
     */
    public function sign(JWK $key, string $input): string;

    /**
     * Verify the signature of data.
     *
     * @param JWK    $key       The private key used to sign the data
     * @param string $input     The input
     * @param string $signature The signature to verify
     *
     * @throws \Exception If key does not support the algorithm or if the key usage does not authorize the operation
     */
    public function verify(JWK $key, string $input, string $signature): bool;
}
