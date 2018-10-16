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

final class ZLib implements CompressionMethod
{
    /**
     * @var int
     */
    private $compression_level = -1;

    /**
     * ZLib constructor.
     */
    public function __construct(int $compression_level = -1)
    {
        if (-1 > $compression_level || 9 < $compression_level) {
            throw new \InvalidArgumentException('The compression level can be given as 0 for no compression up to 9 for maximum compression. If -1 given, the default compression level will be the default compression level of the zlib library.');
        }

        $this->compression_level = $compression_level;
    }

    private function getCompressionLevel(): int
    {
        return $this->compression_level;
    }

    public function name(): string
    {
        return 'ZLIB';
    }

    public function compress(string $data): string
    {
        $data = \gzcompress($data, $this->getCompressionLevel());
        if (false === $data) {
            throw new \InvalidArgumentException('Unable to compress data.');
        }

        return $data;
    }

    public function uncompress(string $data): string
    {
        $data = \gzuncompress($data);
        if (false === $data) {
            throw new \InvalidArgumentException('Unable to uncompress data.');
        }

        return $data;
    }
}
