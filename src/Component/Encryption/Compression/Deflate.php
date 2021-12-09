<?php

declare(strict_types=1);

namespace Jose\Component\Encryption\Compression;

use InvalidArgumentException;
use function is_string;
use Throwable;

final class Deflate implements CompressionMethod
{
    private int $compressionLevel = -1;

    public function __construct(int $compressionLevel = -1)
    {
        if ($compressionLevel < -1 || $compressionLevel > 9) {
            throw new InvalidArgumentException(
                'The compression level can be given as 0 for no compression up to 9 for maximum compression. If -1 given, the default compression level will be the default compression level of the zlib library.'
            );
        }
        $this->compressionLevel = $compressionLevel;
    }

    public function name(): string
    {
        return 'DEF';
    }

    public function compress(string $data): string
    {
        try {
            $bin = gzdeflate($data, $this->getCompressionLevel());
            if (! is_string($bin)) {
                throw new InvalidArgumentException('Unable to encode the data');
            }

            return $bin;
        } catch (Throwable $throwable) {
            throw new InvalidArgumentException('Unable to compress data.', $throwable->getCode(), $throwable);
        }
    }

    public function uncompress(string $data): string
    {
        try {
            $bin = gzinflate($data);
            if (! is_string($bin)) {
                throw new InvalidArgumentException('Unable to encode the data');
            }

            return $bin;
        } catch (Throwable $throwable) {
            throw new InvalidArgumentException('Unable to uncompress data.', $throwable->getCode(), $throwable);
        }
    }

    private function getCompressionLevel(): int
    {
        return $this->compressionLevel;
    }
}
