<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Encryption;

use PHPUnit\Framework\Attributes\Test;
use InvalidArgumentException;
use Jose\Component\Encryption\Compression\CompressionMethodManager;
use Jose\Component\Encryption\Compression\Deflate;

/**
 * Class CompressionTest.
 *
 * @internal
 */
final class CompressionTestCase extends EncryptionTestCase
{
    #[Test]
    public function getValidCompressionAlgorithm(): void
    {
        $manager = new CompressionMethodManager([new Deflate()]);

        static::assertSame(['DEF'], $manager->list());
        $manager->get('DEF');
    }

    #[Test]
    public function getInvalidCompressionAlgorithm(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The compression method "FOO" is not supported.');

        $manager = new CompressionMethodManager([]);
        static::assertFalse($manager->has('FOO'));
        $manager->get('FOO');
    }

    #[Test]
    public function deflate(): void
    {
        $compression = new Deflate(9);

        $data = 'Live long and Prosper.';
        $compressed = $compression->compress($data);
        $uncompressed = $compression->uncompress($compressed);
        static::assertNotNull($compressed);
        static::assertSame($data, $uncompressed);
    }

    #[Test]
    public function deflateInvalidCompressionLevel(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'The compression level can be given as 0 for no compression up to 9 for maximum compression. If -1 given, the default compression level will be the default compression level of the zlib library.'
        );

        new Deflate(100);
    }
}
