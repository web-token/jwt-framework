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

use Jose\Bundle\JoseFramework\Services\JWSVerifierFactory as JWSVerifierFactoryService;
use Jose\Component\Signature\JWSBuilderFactory;
use Jose\Component\Signature\JWSVerifier;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * @group Bundle
 * @group functional
 *
 * @internal
 */
class JWSVerifierTest extends WebTestCase
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
    public function jWSVerifierFactoryIsAvailable(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertInstanceOf(ContainerInterface::class, $container);
        static::assertTrue($container->has(JWSVerifierFactoryService::class));
    }

    /**
     * @test
     */
    public function jWSVerifierFactoryCanCreateAJWSVerifier(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertInstanceOf(ContainerInterface::class, $container);

        $jwsFactory = $container->get(JWSVerifierFactoryService::class);
        static::assertInstanceOf(JWSVerifierFactoryService::class, $jwsFactory);

        $jwsFactory->create(['none']);
    }

    /**
     * @test
     */
    public function jWSVerifierFromConfigurationIsAvailable(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertInstanceOf(ContainerInterface::class, $container);
        static::assertTrue($container->has('jose.jws_verifier.loader1'));

        $jws = $container->get('jose.jws_verifier.loader1');
        static::assertInstanceOf(JWSVerifier::class, $jws);
    }

    /**
     * @test
     */
    public function jWSVerifierFromExternalBundleExtensionIsAvailable(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertInstanceOf(ContainerInterface::class, $container);
        static::assertTrue($container->has('jose.jws_verifier.loader2'));

        $jws = $container->get('jose.jws_verifier.loader2');
        static::assertInstanceOf(JWSVerifier::class, $jws);
    }
}
