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

/**
 * This interface is used by all compression methods.
 */
interface CompressionMethod
{
    /**
     * @return string Return the name of the method
     */
    public function name(): string;

    /**
     * Compress the data.
     *
     * @param string $data The data to compress
     *
     * @throws \RuntimeException
     *
     * @return string The compressed data
     */
    public function compress(string $data): string;

    /**
     * Uncompress the data.
     *
     * @param string $data The data to uncompress
     *
     * @throws \RuntimeException
     *
     * @return string The uncompressed data
     */
    public function uncompress(string $data): string;
}
