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

namespace Jose\Component\Encryption\Tests;

use Jose\Component\Encryption\Compression\CompressionMethod;
use Jose\Component\Encryption\Compression\CompressionMethodManager;
use Jose\Component\Encryption\Compression\Deflate;
use Jose\Component\Encryption\Compression\GZip;
use Jose\Component\Encryption\Compression\ZLib;

/**
 * Class CompressionTest.
 *
 * @group Unit
 */
final class CompressionTest extends EncryptionTest
{
    public function testGetValidCompressionAlgorithm()
    {
        $manager = CompressionMethodManager::create([
            new Deflate(),
            new GZip(),
            new ZLib(),
        ]);

        self::assertEquals(['DEF', 'GZ', 'ZLIB'], $manager->list());
        $compression = $manager->get('DEF');
        self::assertInstanceOf(CompressionMethod::class, $compression);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The compression method "FOO" is not supported.
     */
    public function testGetInvalidCompressionAlgorithm()
    {
        $manager = new CompressionMethodManager();
        self::assertFalse($manager->has('FOO'));
        $manager->get('FOO');
    }

    public function testDeflate()
    {
        $compression = new Deflate(9);

        $data = 'Live long and Prosper.';
        $compressed = $compression->compress($data);
        $uncompressed = $compression->uncompress($compressed);
        self::assertNotNull($compressed);
        self::assertSame($data, $uncompressed);
    }

    public function testGZip()
    {
        $compression = new GZip(9);

        $data = 'Live long and Prosper.';
        $compressed = $compression->compress($data);
        $uncompressed = $compression->uncompress($compressed);
        self::assertNotNull($compressed);
        self::assertSame($data, $uncompressed);
    }

    public function testZLib()
    {
        $compression = new ZLib(9);

        $data = 'Live long and Prosper.';
        $compressed = $compression->compress($data);
        $uncompressed = $compression->uncompress($compressed);
        self::assertNotNull($compressed);
        self::assertSame($data, $uncompressed);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The compression level can be given as 0 for no compression up to 9 for maximum compression. If -1 given, the default compression level will be the default compression level of the zlib library.
     */
    public function testDeflateInvalidCompressionLevel()
    {
        new Deflate(100);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The compression level can be given as 0 for no compression up to 9 for maximum compression. If -1 given, the default compression level will be the default compression level of the zlib library.
     */
    public function testGZipInvalidCompressionLevel()
    {
        new GZip(100);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The compression level can be given as 0 for no compression up to 9 for maximum compression. If -1 given, the default compression level will be the default compression level of the zlib library.
     */
    public function testZLibInvalidCompressionLevel()
    {
        new ZLib(100);
    }
}
