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

namespace Jose\Tests\Bundle\JoseFramework\Functional\Signature;

use Jose\Bundle\JoseFramework\Services\JWSBuilder;
use Jose\Bundle\JoseFramework\Services\JWSBuilderFactory as JWSBuilderFactoryService;
use Jose\Component\Signature\JWSBuilderFactory;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * @group Bundle
 * @group functional
 *
 * @internal
 */
class JWSBuilderTest extends WebTestCase
{
    protected function setUp(): void
    {
        if (!class_exists(JWSBuilderFactory::class)) {
            static::markTestSkipped('The component "web-token/jwt-signature" is not installed.');
        }
    }

    /**
     * @test
     */
    public function jWSBuilderFactoryIsAvailable(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertInstanceOf(ContainerInterface::class, $container);
        static::assertTrue($container->has(JWSBuilderFactoryService::class));
    }

    /**
     * @test
     */
    public function jWSBuilderFactoryCanCreateAJWSBuilder(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertInstanceOf(ContainerInterface::class, $container);

        /** @var JWSBuilderFactory $jwsFactory */
        $jwsFactory = $container->get(JWSBuilderFactoryService::class);

        $jws = $jwsFactory->create(['none']);

        static::assertInstanceOf(JWSBuilder::class, $jws);
    }

    /**
     * @test
     */
    public function jWSBuilderFromConfigurationIsAvailable(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertInstanceOf(ContainerInterface::class, $container);
        static::assertTrue($container->has('jose.jws_builder.builder1'));

        $jws = $container->get('jose.jws_builder.builder1');
        static::assertInstanceOf(JWSBuilder::class, $jws);
    }

    /**
     * @test
     */
    public function jWSBuilderFromExternalBundleExtensionIsAvailable(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertInstanceOf(ContainerInterface::class, $container);
        static::assertTrue($container->has('jose.jws_builder.builder2'));

        $jws = $container->get('jose.jws_builder.builder2');
        static::assertInstanceOf(JWSBuilder::class, $jws);
    }
}
