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

namespace Jose\Component\Encryption\Compression;

interface CompressionMethod
{
    /**
     * Returns the name of the method.
     */
    public function name(): string;

    /**
     * Compress the data.
     * Throws an exception in case of failure.
     *
     * @param string $data The data to compress
     *
     * @throws \RuntimeException
     */
    public function compress(string $data): string;

    /**
     * Uncompress the data.
     * Throws an exception in case of failure.
     *
     * @param string $data The data to uncompress
     *
     * @throws \RuntimeException
     */
    public function uncompress(string $data): string;
}
