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

use Jose\Bundle\JoseFramework\Services\JWEDecrypterFactory as JWEDecrypterFactoryService;
use Jose\Component\Encryption\JWEBuilderFactory;
use Jose\Component\Encryption\JWEDecrypter;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * @group Bundle
 * @group functional
 *
 * @internal
 */
class JWEDecrypterTest extends WebTestCase
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
    public function theJWEDecrypterFactoryIsAvailable(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertInstanceOf(ContainerInterface::class, $container);
        static::assertTrue($container->has(JWEDecrypterFactoryService::class));
    }

    /**
     * @test
     */
    public function theWEDecrypterFactoryCanCreateAJWEDecrypter(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertInstanceOf(ContainerInterface::class, $container);

        $jweFactory = $container->get(JWEDecrypterFactoryService::class);
        static::assertInstanceOf(JWEDecrypterFactoryService::class, $jweFactory);

        $jweFactory->create(['RSA1_5'], ['A256GCM'], ['DEF']);
    }

    /**
     * @test
     */
    public function aJWEDecrypterCanBeDefinedUsingTheConfigurationFile(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertInstanceOf(ContainerInterface::class, $container);
        static::assertTrue($container->has('jose.jwe_decrypter.loader1'));

        $jwe = $container->get('jose.jwe_decrypter.loader1');
        static::assertInstanceOf(JWEDecrypter::class, $jwe);
    }

    /**
     * @test
     */
    public function aJWEDecrypterCanBeDefinedFromAnotherBundleUsingTheHelper(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertInstanceOf(ContainerInterface::class, $container);
        static::assertTrue($container->has('jose.jwe_decrypter.loader2'));

        $jwe = $container->get('jose.jwe_decrypter.loader2');
        static::assertInstanceOf(JWEDecrypter::class, $jwe);
    }
}
