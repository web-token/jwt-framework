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

namespace Jose\Component\Encryption\Serializer;

use Jose\Component\Encryption\JWE;

/**
 * Interface JWESerializer.
 */
interface JWESerializer
{
    /**
     * The name of the serialization.
     *
     * @return string
     */
    public function name(): string;

    /**
     * @return string
     */
    public function displayName(): string;

    /**
     * Converts a JWE into a string.
     *
     * @param JWE      $jws
     * @param int|null $recipientIndex
     *
     * @throws \Exception
     *
     * @return string
     */
    public function serialize(JWE $jws, ?int $recipientIndex = null): string;

    /**
     * Loads data and return a JWE object.
     *
     * @param string $input A string that represents a JWE
     *
     * @throws \Exception
     *
     * @return JWE
     */
    public function unserialize(string $input): JWE;
}
