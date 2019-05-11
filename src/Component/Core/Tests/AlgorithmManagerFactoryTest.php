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

namespace Jose\Component\Core\Tests;

use Jose\Component\Core\Algorithm;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\AlgorithmManagerFactory;
use PHPUnit\Framework\TestCase;

/**
 * @group unit
 * @group JWAManager
 *
 * @internal
 * @coversNothing
 */
class AlgorithmManagerFactoryTest extends TestCase
{
    /**
     * @var null|AlgorithmManagerFactory
     */
    private $algorithmManagerFactory;

    /**
     * @test
     */
    public function iCanListSupportedAliases()
    {
        static::assertEquals(['foo'], $this->getAlgorithmManagerFactory()->aliases());
        static::assertEquals(['foo'], array_keys($this->getAlgorithmManagerFactory()->all()));
    }

    /**
     * @test
     */
    public function iCanCreateAnAlgorithmManagerUsingAliases()
    {
        static::assertInstanceOf(AlgorithmManager::class, $this->getAlgorithmManagerFactory()->create(['foo']));
    }

    /**
     * @test
     */
    public function iCannotCreateAnAlgorithmManagerWithABadArgument()
    {
        $this->expectException(\TypeError::class);

        new AlgorithmManager(['foo']);
    }

    /**
     * @test
     */
    public function iCannotGetAnAlgorithmThatDoesNotExist()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The algorithm "HS384" is not supported.');

        $manager = new AlgorithmManager([new FooAlgorithm()]);

        static::assertEquals(['foo'], $manager->list());
        static::assertTrue($manager->has('foo'));
        static::assertFalse($manager->has('HS384'));
        static::assertInstanceOf(Algorithm::class, $manager->get('foo'));
        $manager->get('HS384');
    }

    private function getAlgorithmManagerFactory(): AlgorithmManagerFactory
    {
        if (null === $this->algorithmManagerFactory) {
            $this->algorithmManagerFactory = new AlgorithmManagerFactory();
            $this->algorithmManagerFactory->add('foo', new FooAlgorithm());
        }

        return $this->algorithmManagerFactory;
    }
}
