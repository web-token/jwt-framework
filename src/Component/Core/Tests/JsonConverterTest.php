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

namespace Jose\Component\Core\Tests;

use Jose\Component\Core\Util\JsonConverter;
use PHPUnit\Framework\TestCase;

/**
 * @group unit
 * @group JsonConverter
 *
 * @internal
 */
class JsonConverterTest extends TestCase
{
    /**
     * @test
     */
    public function iCanConvertAnObjectIntoAJsonString(): void
    {
        static::assertEquals('{"foo":"BAR"}', JsonConverter::encode(['foo' => 'BAR']));
        static::assertEquals(['foo' => 'BAR'], JsonConverter::decode('{"foo":"BAR"}'));
    }
}
