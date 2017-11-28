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

namespace Jose\Bundle\JoseFramework\Tests\Functional\Core;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\AlgorithmManagerFactory;
use Jose\Component\Core\Converter\JsonConverter;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

/**
 * @group Bundle
 * @group Functional
 */
final class AlgorithmManagerTest extends WebTestCase
{
    /**
     * @test
     */
    public function theAlgorithmManagerFactoryIsAvailable()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        self::assertNotNull($container);
        self::assertTrue($container->has(AlgorithmManagerFactory::class));
    }

    /**
     * @test
     */
    public function theAlgorithmManagerFactoryCanCreateAnAlgorithmManager()
    {
        $client = static::createClient();
        /** @var AlgorithmManagerFactory $algorithmManagerFactory */
        $algorithmManagerFactory = $client->getContainer()->get(AlgorithmManagerFactory::class);

        $aliases = $algorithmManagerFactory->aliases();
        $algorithmManager = $algorithmManagerFactory->create($aliases);

        self::assertInstanceOf(AlgorithmManager::class, $algorithmManager);
    }

    /**
     * @test
     */
    public function aJsonConverterIsAvailable()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        self::assertNotNull($container);
        self::assertTrue($container->has(JsonConverter::class));
        self::assertInstanceOf(JsonConverter::class, $container->get(JsonConverter::class));
    }
}
