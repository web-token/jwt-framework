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

namespace Jose\Component\Core\Converter;

interface JsonConverter
{
    /**
     * Convert the payload into a string.
     *
     * @param mixed $payload
     *
     * @return string
     */
    public function encode($payload): string;

    /**
     * Convert a string into payload.
     *
     * @param string $payload
     * @param bool   $associativeArray
     *
     * @return mixed
     */
    public function decode(string $payload, bool $associativeArray = true);
}
