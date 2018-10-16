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

namespace Jose\Component\Core\Tests;

use Jose\Component\Core\Converter\StandardConverter;
use PHPUnit\Framework\TestCase;

/**
 * @group Unit
 * @group JsonConverter
 */
class JsonConverterTest extends TestCase
{
    /**
     * @test
     */
    public function iCanConvertAnObjectIntoAJsonString()
    {
        $converter = new StandardConverter();
        static::assertEquals('{"foo":"BAR"}', $converter->encode(['foo' => 'BAR']));
        static::assertEquals(['foo' => 'BAR'], $converter->decode('{"foo":"BAR"}'));
    }
}
