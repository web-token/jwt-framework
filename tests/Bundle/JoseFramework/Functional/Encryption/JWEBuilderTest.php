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

namespace Jose\Tests\Bundle\JoseFramework\Functional\Encryption;

use Jose\Bundle\JoseFramework\Services\JWEBuilder;
use Jose\Bundle\JoseFramework\Services\JWEBuilderFactory as JWEBuilderFactoryService;
use Jose\Component\Encryption\JWEBuilderFactory;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * @group Bundle
 * @group functional
 *
 * @internal
 */
class JWEBuilderTest extends WebTestCase
{
    protected function setUp(): void
    {
        if (!class_exists(JWEBuilderFactory::class)) {
            static::markTestSkipped('The component "web-token/jwt-encryption" is not installed.');
        }
    }

    /**
     * @test
     */
    public function theJWEBuilderFactoryIsAvailable(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertInstanceOf(ContainerInterface::class, $container);
        static::assertTrue($container->has(JWEBuilderFactoryService::class));
    }

    /**
     * @test
     */
    public function theJWEBuilderFactoryCanCreateAJWEBuilder(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertInstanceOf(ContainerInterface::class, $container);

        $jweFactory = $container->get(JWEBuilderFactoryService::class);
        static::assertInstanceOf(JWEBuilderFactoryService::class, $jweFactory);

        $jweFactory->create(['RSA1_5'], ['A256GCM'], ['DEF']);
    }

    /**
     * @test
     */
    public function aJWEBuilderCanBeDefinedUsingTheConfigurationFile(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertInstanceOf(ContainerInterface::class, $container);
        static::assertTrue($container->has('jose.jwe_builder.builder1'));

        $jwe = $container->get('jose.jwe_builder.builder1');
        static::assertInstanceOf(JWEBuilder::class, $jwe);
    }

    /**
     * @test
     */
    public function aJWEBuilderCanBeDefinedFromAnotherBundleUsingTheHelper(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertInstanceOf(ContainerInterface::class, $container);
        static::assertTrue($container->has('jose.jwe_builder.builder2'));

        $jwe = $container->get('jose.jwe_builder.builder2');
        static::assertInstanceOf(JWEBuilder::class, $jwe);
    }
}
