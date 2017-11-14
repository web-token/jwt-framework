<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Core\Tests;

use Jose\Component\Core\Algorithm;
use Jose\Component\Core\AlgorithmManager;
use PHPUnit\Framework\TestCase;

/**
 * Class AlgorithmManagerTest.
 *
 * @group Unit
 * @group JWAManager
 */
final class AlgorithmManagerTest extends TestCase
{
    /**
     * @test
     * @expectedException \TypeError
     */
    public function iCannotCreateAnAlgorithmManagerWithABadArgument()
    {
        AlgorithmManager::create(['foo']);
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The algorithm "HS384" is not supported.
     */
    public function iCannotGetAnAlgorithmThatDoesNotExist()
    {
        $manager = AlgorithmManager::create([new FooAlgorithm()]);

        self::assertEquals(['foo'], $manager->list());
        self::assertTrue($manager->has('foo'));
        self::assertFalse($manager->has('HS384'));
        self::assertInstanceOf(Algorithm::class, $manager->get('foo'));
        $manager->get('HS384');
    }
}
