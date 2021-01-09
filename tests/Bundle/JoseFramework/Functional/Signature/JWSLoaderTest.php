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

use Jose\Bundle\JoseFramework\Services\JWSLoaderFactory as JWSLoaderFactoryService;
use Jose\Component\Signature\JWSLoader;
use Jose\Component\Signature\JWSLoaderFactory;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * @group Bundle
 * @group functional
 *
 * @internal
 */
class JWSLoaderTest extends WebTestCase
{
    protected function setUp(): void
    {
        if (!class_exists(JWSLoaderFactory::class)) {
            static::markTestSkipped('The component "web-token/jwt-signature" is not installed.');
        }
    }

    /**
     * @test
     */
    public function theJWSLoaderFactoryIsAvailable(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertInstanceOf(ContainerInterface::class, $container);
        static::assertTrue($container->has(JWSLoaderFactoryService::class));
    }

    /**
     * @test
     */
    public function theWELoaderFactoryCanCreateAJWSLoader(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertInstanceOf(ContainerInterface::class, $container);

        /** @var JWSLoaderFactory $jwsLoaderFactory */
        $jwsLoaderFactory = $container->get(JWSLoaderFactoryService::class);

        $jws = $jwsLoaderFactory->create(['jws_compact'], ['RS512']);

        static::assertEquals(['jws_compact'], $jws->getSerializerManager()->list());
        static::assertEquals(['RS512'], $jws->getJwsVerifier()->getSignatureAlgorithmManager()->list());
    }

    /**
     * @test
     */
    public function aJWSLoaderCanBeDefinedUsingTheConfigurationFile(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertInstanceOf(ContainerInterface::class, $container);
        static::assertTrue($container->has('jose.jws_loader.jws_loader1'));

        $jws = $container->get('jose.jws_loader.jws_loader1');
        static::assertInstanceOf(JWSLoader::class, $jws);
    }

    /**
     * @test
     */
    public function aJWSLoaderCanBeDefinedFromAnotherBundleUsingTheHelper(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertInstanceOf(ContainerInterface::class, $container);
        static::assertTrue($container->has('jose.jws_loader.jws_loader2'));

        $jws = $container->get('jose.jws_loader.jws_loader2');
        static::assertInstanceOf(JWSLoader::class, $jws);
    }
}
