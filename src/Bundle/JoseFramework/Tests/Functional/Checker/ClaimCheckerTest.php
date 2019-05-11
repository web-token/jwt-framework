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

use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Checker\ClaimCheckerManagerFactory;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

/**
 * @group Bundle
 * @group functional
 *
 * @internal
 * @coversNothing
 */
class ClaimCheckerTest extends WebTestCase
{
    protected function setUp(): void
    {
        if (!class_exists(ClaimCheckerManagerFactory::class)) {
            static::markTestSkipped('The component "web-token/jwt-checker" is not installed.');
        }
    }

    /**
     * @test
     */
    public function theClaimCheckerManagerFactoryIsAvailable()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertNotNull($container);
        static::assertTrue($container->has(\Jose\Bundle\JoseFramework\Services\ClaimCheckerManagerFactory::class));
    }

    /**
     * @test
     */
    public function theClaimCheckerManagerFactoryCanCreateAClaimCheckerManager()
    {
        $client = static::createClient();
        /** @var ClaimCheckerManagerFactory $claimCheckerManagerFactory */
        $claimCheckerManagerFactory = $client->getContainer()->get(\Jose\Bundle\JoseFramework\Services\ClaimCheckerManagerFactory::class);

        $aliases = $claimCheckerManagerFactory->aliases();
        $claimCheckerManager = $claimCheckerManagerFactory->create($aliases);

        static::assertInstanceOf(ClaimCheckerManager::class, $claimCheckerManager);
    }

    /**
     * @test
     */
    public function aClaimCheckerCanBeDefinedUsingTheConfigurationFile()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertTrue($container->has('jose.claim_checker.checker1'));

        $claimCheckerManager = $container->get('jose.claim_checker.checker1');
        static::assertInstanceOf(ClaimCheckerManager::class, $claimCheckerManager);
    }

    /**
     * @test
     */
    public function aClaimCheckerCanBeDefinedFromAnotherBundleUsingTheHelper()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertTrue($container->has('jose.claim_checker.checker2'));

        $claimCheckerManager = $container->get('jose.claim_checker.checker2');
        static::assertInstanceOf(ClaimCheckerManager::class, $claimCheckerManager);
    }
}
