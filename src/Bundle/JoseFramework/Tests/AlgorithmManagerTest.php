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

namespace Jose\Bundle\JoseFramework\Tests;

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
    public function testAlgorithmManagerFactoryIsAvailable()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        self::assertNotNull($container);
        self::assertTrue($container->has(AlgorithmManagerFactory::class));
    }

    public function testAlgorithmManagerFactoryCanCreateAnAlgorithmManager()
    {
        $client = static::createClient();
        /** @var AlgorithmManagerFactory $algorithmManagerFactory */
        $algorithmManagerFactory = $client->getContainer()->get(AlgorithmManagerFactory::class);

        $aliases = $algorithmManagerFactory->aliases();
        $algorithmManager = $algorithmManagerFactory->create($aliases);

        self::assertInstanceOf(AlgorithmManager::class, $algorithmManager);
    }

    public function testAJsonConverterIsAvailable()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        self::assertNotNull($container);
        self::assertTrue($container->has(JsonConverter::class));
    }
}
