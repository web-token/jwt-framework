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

namespace Jose\Bundle\JoseFramework\Tests\Functional\Checker;

use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Checker\HeaderCheckerManagerFactory;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

/**
 * @group Bundle
 * @group functional
 *
 * @internal
 * @coversNothing
 */
class HeaderCheckerTest extends WebTestCase
{
    protected function setUp(): void
    {
        if (!class_exists(HeaderCheckerManagerFactory::class)) {
            static::markTestSkipped('The component "web-token/jwt-checker" is not installed.');
        }
    }

    /**
     * @test
     */
    public function theHeaderCheckerManagerFactoryIsAvailable()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertNotNull($container);
        static::assertTrue($container->has(\Jose\Bundle\JoseFramework\Services\HeaderCheckerManagerFactory::class));
    }

    /**
     * @test
     */
    public function theHeaderCheckerManagerFactoryCanCreateAHeaderCheckerManager()
    {
        $client = static::createClient();
        /** @var HeaderCheckerManagerFactory $headerCheckerManagerFactory */
        $headerCheckerManagerFactory = $client->getContainer()->get(\Jose\Bundle\JoseFramework\Services\HeaderCheckerManagerFactory::class);

        $aliases = $headerCheckerManagerFactory->aliases();
        $headerCheckerManager = $headerCheckerManagerFactory->create($aliases);

        static::assertInstanceOf(HeaderCheckerManager::class, $headerCheckerManager);
    }

    /**
     * @test
     */
    public function aHeaderCheckerCanBeDefinedUsingTheConfigurationFile()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertTrue($container->has('jose.header_checker.checker1'));

        $headerCheckerManager = $container->get('jose.header_checker.checker1');
        static::assertInstanceOf(HeaderCheckerManager::class, $headerCheckerManager);
    }

    /**
     * @test
     */
    public function aHeaderCheckerCanBeDefinedFromAnotherBundleUsingTheHelper()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertTrue($container->has('jose.header_checker.checker2'));

        $headerCheckerManager = $container->get('jose.header_checker.checker2');
        static::assertInstanceOf(HeaderCheckerManager::class, $headerCheckerManager);
    }
}
