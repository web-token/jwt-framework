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

namespace Jose\Bundle\JoseFramework\Tests\Functional\Signature;

use Jose\Component\Signature\JWSLoader;
use Jose\Component\Signature\JWSLoaderFactory;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

/**
 * @group Bundle
 * @group functional
 *
 * @internal
 * @coversNothing
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
    public function theJWSLoaderFactoryIsAvailable()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertNotNull($container);
        static::assertTrue($container->has(\Jose\Bundle\JoseFramework\Services\JWSLoaderFactory::class));
    }

    /**
     * @test
     */
    public function theWELoaderFactoryCanCreateAJWSLoader()
    {
        $client = static::createClient();

        /** @var JWSLoaderFactory $jwsLoaderFactory */
        $jwsLoaderFactory = $client->getContainer()->get(\Jose\Bundle\JoseFramework\Services\JWSLoaderFactory::class);

        $jws = $jwsLoaderFactory->create(['jws_compact'], ['RS512']);

        static::assertInstanceOf(JWSLoader::class, $jws);
        static::assertEquals(['jws_compact'], $jws->getSerializerManager()->list());
        static::assertEquals(['RS512'], $jws->getJwsVerifier()->getSignatureAlgorithmManager()->list());
    }

    /**
     * @test
     */
    public function aJWSLoaderCanBeDefinedUsingTheConfigurationFile()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertTrue($container->has('jose.jws_loader.jws_loader1'));

        $jws = $container->get('jose.jws_loader.jws_loader1');
        static::assertInstanceOf(JWSLoader::class, $jws);
    }

    /**
     * @test
     */
    public function aJWSLoaderCanBeDefinedFromAnotherBundleUsingTheHelper()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertTrue($container->has('jose.jws_loader.jws_loader2'));

        $jws = $container->get('jose.jws_loader.jws_loader2');
        static::assertInstanceOf(JWSLoader::class, $jws);
    }
}
