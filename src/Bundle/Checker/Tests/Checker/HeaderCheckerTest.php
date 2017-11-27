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

namespace Jose\Bundle\Checker\Tests\Checker;

use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Checker\HeaderCheckerManagerFactory;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

/**
 * @group Bundle
 * @group Functional
 */
final class HeaderCheckerTest extends WebTestCase
{
    public function testHeaderCheckerManagerFactoryIsAvailable()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        self::assertNotNull($container);
        self::assertTrue($container->has(HeaderCheckerManagerFactory::class));
    }

    public function testHeaderCheckerManagerFactoryCanCreateAHeaderCheckerManager()
    {
        $client = static::createClient();
        /** @var HeaderCheckerManagerFactory $headerCheckerManagerFactory */
        $headerCheckerManagerFactory = $client->getContainer()->get(HeaderCheckerManagerFactory::class);

        $aliases = $headerCheckerManagerFactory->aliases();
        $headerCheckerManager = $headerCheckerManagerFactory->create($aliases);

        self::assertInstanceOf(HeaderCheckerManager::class, $headerCheckerManager);
    }

    public function testHeaderCheckerFromConfigurationIsAvailable()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        self::assertTrue($container->has('jose.header_checker.checker1'));

        $headerCheckerManager = $container->get('jose.header_checker.checker1');
        self::assertInstanceOf(HeaderCheckerManager::class, $headerCheckerManager);
    }

    public function testHeaderCheckerFromExternalBundleExtensionIsAvailable()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        self::assertTrue($container->has('jose.header_checker.checker2'));

        $headerCheckerManager = $container->get('jose.header_checker.checker2');
        self::assertInstanceOf(HeaderCheckerManager::class, $headerCheckerManager);
    }
}
