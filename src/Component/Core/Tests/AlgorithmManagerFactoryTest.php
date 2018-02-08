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

use Jose\Component\Core\Algorithm;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\AlgorithmManagerFactory;
use PHPUnit\Framework\TestCase;

/**
 * @group Unit
 * @group JWAManager
 */
class AlgorithmManagerFactoryTest extends TestCase
{
    /**
     * @test
     */
    public function iCanListSupportedAliases()
    {
        self::assertEquals(['foo'], $this->getAlgorithmManagerFactory()->aliases());
        self::assertEquals(['foo'], array_keys($this->getAlgorithmManagerFactory()->all()));
    }

    /**
     * @test
     */
    public function iCanCreateAnAlgorithmManagerUsingAliases()
    {
        self::assertInstanceOf(AlgorithmManager::class, $this->getAlgorithmManagerFactory()->create(['foo']));
    }

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

    /**
     * @var null|AlgorithmManagerFactory
     */
    private $algorithmManagerFactory;

    /**
     * @return AlgorithmManagerFactory
     */
    private function getAlgorithmManagerFactory(): AlgorithmManagerFactory
    {
        if (null === $this->algorithmManagerFactory) {
            $this->algorithmManagerFactory = new AlgorithmManagerFactory();
            $this->algorithmManagerFactory->add('foo', new FooAlgorithm());
        }

        return $this->algorithmManagerFactory;
    }
}
