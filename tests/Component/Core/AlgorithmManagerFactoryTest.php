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

namespace Jose\Tests\Component\Core;

use InvalidArgumentException;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\AlgorithmManagerFactory;
use PHPUnit\Framework\TestCase;
use TypeError;

/**
 * @group unit
 * @group JWAManager
 *
 * @internal
 */
class AlgorithmManagerFactoryTest extends TestCase
{
    /**
     * @var null|AlgorithmManagerFactory
     */
    private $algorithmManagerFactory;

    /**
     * @test
     * @covers \Jose\Component\Core\AlgorithmManagerFactory
     */
    public function iCanListSupportedAliases(): void
    {
        static::assertEquals(['foo'], $this->getAlgorithmManagerFactory()->aliases());
        static::assertEquals(['foo'], array_keys($this->getAlgorithmManagerFactory()->all()));
    }

    /**
     * @test
     * @covers \Jose\Component\Core\AlgorithmManager
     */
    public function iCannotCreateAnAlgorithmManagerWithABadArgument(): void
    {
        $this->expectException(TypeError::class);

        new AlgorithmManager(['foo']);
    }

    /**
     * @test
     * @covers \Jose\Component\Core\AlgorithmManager
     */
    public function iCannotGetAnAlgorithmThatDoesNotExist(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The algorithm "HS384" is not supported.');

        $manager = new AlgorithmManager([new FooAlgorithm()]);

        static::assertEquals(['foo'], $manager->list());
        static::assertTrue($manager->has('foo'));
        static::assertFalse($manager->has('HS384'));
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
