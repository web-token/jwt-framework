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

namespace Jose\Tests\Bundle\JoseFramework\Functional\KeyManagement;

use Base64Url\Base64Url;
use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactory;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * @group Bundle
 * @group functional
 * @group KeyManagement
 *
 * @internal
 */
class JWKLoaderTest extends WebTestCase
{
    protected function setUp(): void
    {
        if (!class_exists(JWKFactory::class)) {
            static::markTestSkipped('The component "web-token/jwt-key-mgmt" is not installed.');
        }
    }

    /**
     * @test
     */
    public function aJWKCanBeDefinedInTheConfiguration(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();

        $container = $client->getContainer();
        static::assertInstanceOf(ContainerInterface::class, $container);
        static::assertTrue($container->has('jose.key.jwk1'));
        static::assertInstanceOf(JWK::class, $container->get('jose.key.jwk1'));
    }

    /**
     * @test
     */
    public function aJWKCanBeDefinedFromAnotherBundle(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();

        $container = $client->getContainer();
        static::assertInstanceOf(ContainerInterface::class, $container);
        static::assertTrue($container->has('jose.key.jwk2'));
        static::assertInstanceOf(JWK::class, $container->get('jose.key.jwk2'));
    }

    /**
     * @test
     */
    public function aX509InFileCanBeDefinedInTheConfiguration(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();

        $container = $client->getContainer();
        static::assertInstanceOf(ContainerInterface::class, $container);
        static::assertTrue($container->has('jose.key.certificate1'));
        static::assertInstanceOf(JWK::class, $container->get('jose.key.certificate1'));
    }

    /**
     * @test
     */
    public function aDirectX509InputCanBeDefinedInTheConfiguration(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();

        $container = $client->getContainer();
        static::assertInstanceOf(ContainerInterface::class, $container);
        static::assertTrue($container->has('jose.key.x5c1'));
        static::assertInstanceOf(JWK::class, $container->get('jose.key.x5c1'));
    }

    /**
     * @test
     */
    public function anEncryptedKeyFileCanBeLoadedInTheConfiguration(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();

        $container = $client->getContainer();
        static::assertInstanceOf(ContainerInterface::class, $container);
        static::assertTrue($container->has('jose.key.file1'));
        static::assertInstanceOf(JWK::class, $container->get('jose.key.file1'));
    }

    /**
     * @test
     */
    public function aJWKCanBeLoadedFromAJwkSetInTheConfiguration(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();

        $container = $client->getContainer();
        static::assertInstanceOf(ContainerInterface::class, $container);
        static::assertTrue($container->has('jose.key.jwkset1'));
        static::assertInstanceOf(JWK::class, $container->get('jose.key.jwkset1'));
    }

    /**
     * @test
     */
    public function aJWKCanBeLoadedFromASecretInTheConfiguration(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();

        $container = $client->getContainer();
        static::assertInstanceOf(ContainerInterface::class, $container);
        static::assertTrue($container->has('jose.key.secret1'));
        $jwk = $container->get('jose.key.secret1');

        static::assertInstanceOf(JWK::class, $jwk);
        static::assertEquals('oct', $jwk->get('kty'));
        static::assertEquals('enc', $jwk->get('use'));
        static::assertEquals('RS512', $jwk->get('alg'));
        static::assertEquals('This is my secret', Base64Url::decode($jwk->get('k')));
    }
}
