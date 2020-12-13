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

namespace Jose\Tests\Easy;

use Jose\Easy\ParameterBag;
use PHPUnit\Framework\TestCase;

/**
 * @group easy
 *
 * @internal
 * @covers \Jose\Easy\ParameterBag
 */
class ParameterBagTest extends TestCase
{
    /**
     * @test
     */
    public function basicCalls(): void
    {
        $bag = new ParameterBag();
        $bag->iss('iss');
        $bag->alg('alg');
        $bag->aud(['aud']);

        static::assertEquals(['aud'], $bag->aud());
        static::assertEquals('iss', $bag->get('iss'));
        static::assertEquals('alg', $bag->get('alg'));
    }
}
