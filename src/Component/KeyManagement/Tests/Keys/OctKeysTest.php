<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2019 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\KeyManagement\Tests\Keys;

use Jose\Component\KeyManagement\JWKFactory;
use PHPUnit\Framework\TestCase;

/**
 * @group OctKeys
 * @group unit
 *
 * @internal
 * @coversNothing
 */
class OctKeysTest extends TestCase
{
    /**
     * @test
     */
    public function createOctKeyWithInvalidKeySize()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid key size.');

        JWKFactory::createOctKey(12);
    }

    /**
     * @test
     */
    public function createOctKey()
    {
        $jwk = JWKFactory::createOctKey(64);

        static::assertEquals('oct', $jwk->get('kty'));
        static::assertTrue($jwk->has('k'));
    }
}
