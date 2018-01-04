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

namespace Jose\Bundle\JoseFramework\Tests\Functional\Checker;

use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Checker\HeaderCheckerManagerFactory;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

/**
 * @group Bundle
 * @group Functional
 */
final class HeaderCheckerTest extends WebTestCase
{
    /**
     * {@inheritdoc}
     */
    protected function setUp()
    {
        if (!class_exists(HeaderCheckerManagerFactory::class)) {
            $this->markTestSkipped('The component "web-token/jwt-checker" is not installed.');
        }
    }

    /**
     * @test
     */
    public function theHeaderCheckerManagerFactoryIsAvailable()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        self::assertNotNull($container);
        self::assertTrue($container->has(HeaderCheckerManagerFactory::class));
    }

    /**
     * @test
     */
    public function theHeaderCheckerManagerFactoryCanCreateAHeaderCheckerManager()
    {
        $client = static::createClient();
        /** @var HeaderCheckerManagerFactory $headerCheckerManagerFactory */
        $headerCheckerManagerFactory = $client->getContainer()->get(HeaderCheckerManagerFactory::class);

        $aliases = $headerCheckerManagerFactory->aliases();
        $headerCheckerManager = $headerCheckerManagerFactory->create($aliases);

        self::assertInstanceOf(HeaderCheckerManager::class, $headerCheckerManager);
    }

    /**
     * @test
     */
    public function aHeaderCheckerCanBeDefinedUsingTheConfigurationFile()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        self::assertTrue($container->has('jose.header_checker.checker1'));

        $headerCheckerManager = $container->get('jose.header_checker.checker1');
        self::assertInstanceOf(HeaderCheckerManager::class, $headerCheckerManager);
    }

    /**
     * @test
     */
    public function aHeaderCheckerCanBeDefinedFromAnotherBundleUsingTheHelper()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        self::assertTrue($container->has('jose.header_checker.checker2'));

        $headerCheckerManager = $container->get('jose.header_checker.checker2');
        self::assertInstanceOf(HeaderCheckerManager::class, $headerCheckerManager);
    }
}
