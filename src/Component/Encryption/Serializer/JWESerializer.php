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

namespace Jose\Component\Encryption\Serializer;

use Jose\Component\Encryption\JWE;

interface JWESerializer
{
    /**
     * The name of the serialization method.
     */
    public function name(): string;

    /**
     * Display name of the serialization method.
     */
    public function displayName(): string;

    /**
     * Converts a JWE into a string.
     * If the JWE is designed for multiple recipients and the serializer only supports one recipient,
     * the recipient index has to be set.
     */
    public function serialize(JWE $jws, ?int $recipientIndex = null): string;

    /**
     * Loads data and return a JWE object.
     * Throws an exception in case of failure.
     *
     * @param string $input A string that represents a JWE
     */
    public function unserialize(string $input): JWE;
}
