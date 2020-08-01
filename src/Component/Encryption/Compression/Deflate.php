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

namespace Jose\Component\Encryption\Compression;

use InvalidArgumentException;
use Throwable;

final class Deflate implements CompressionMethod
{
    /**
     * @var int
     */
    private $compressionLevel = -1;

    /**
     * Deflate constructor.
     *
     * @throws InvalidArgumentException if the compression level is invalid
     */
    public function __construct(int $compressionLevel = -1)
    {
        if ($compressionLevel < -1 || $compressionLevel > 9) {
            throw new InvalidArgumentException('The compression level can be given as 0 for no compression up to 9 for maximum compression. If -1 given, the default compression level will be the default compression level of the zlib library.');
        }
        $this->compressionLevel = $compressionLevel;
    }

    public function name(): string
    {
        return 'DEF';
    }

    /**
     * @throws InvalidArgumentException if the compression failed
     */
    public function compress(string $data): string
    {
        try {
            return gzdeflate($data, $this->getCompressionLevel());
        } catch (Throwable $throwable) {
            throw new InvalidArgumentException('Unable to compress data.', $throwable->getCode(), $throwable);
        }
    }

    /**
     * @throws InvalidArgumentException if the decompression failed
     */
    public function uncompress(string $data): string
    {
        try {
            return gzinflate($data);
        } catch (Throwable $throwable) {
            throw new InvalidArgumentException('Unable to uncompress data.', $throwable->getCode(), $throwable);
        }
    }

    private function getCompressionLevel(): int
    {
        return $this->compressionLevel;
    }
}
