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

namespace Jose\Bundle\JoseFramework\Tests\Functional\Signature;

use Jose\Component\Signature\JWSBuilderFactory;
use Jose\Component\Signature\JWSLoader;
use Jose\Component\Signature\JWSLoaderFactory;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

/**
 * @group Bundle
 * @group Functional
 */
class JWSLoaderTest extends WebTestCase
{
    /**
     * {@inheritdoc}
     */
    protected function setUp()
    {
        if (!\class_exists(JWSBuilderFactory::class)) {
            $this->markTestSkipped('The component "web-token/jwt-encryption" is not installed.');
        }
    }

    /**
     * @test
     */
    public function theJWSLoaderFactoryIsAvailable()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        self::assertNotNull($container);
        self::assertTrue($container->has(JWSLoaderFactory::class));
    }

    /**
     * @test
     */
    public function theWELoaderFactoryCanCreateAJWSLoader()
    {
        $client = static::createClient();

        /** @var JWSLoaderFactory $jwsLoaderFactory */
        $jwsLoaderFactory = $client->getContainer()->get(JWSLoaderFactory::class);

        $jws = $jwsLoaderFactory->create(['jws_compact'], ['RS512']);

        self::assertInstanceOf(JWSLoader::class, $jws);
        self::assertEquals(['jws_compact'], $jws->getSerializerManager()->list());
        self::assertEquals(['RS512'], $jws->getJwsVerifier()->getSignatureAlgorithmManager()->list());
    }

    /**
     * @test
     */
    public function aJWSLoaderCanBeDefinedUsingTheConfigurationFile()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        self::assertTrue($container->has('jose.jws_loader.jws_loader1'));

        $jws = $container->get('jose.jws_loader.jws_loader1');
        self::assertInstanceOf(JWSLoader::class, $jws);
    }

    /**
     * @test
     */
    public function aJWSLoaderCanBeDefinedFromAnotherBundleUsingTheHelper()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        self::assertTrue($container->has('jose.jws_loader.jws_loader2'));

        $jws = $container->get('jose.jws_loader.jws_loader2');
        self::assertInstanceOf(JWSLoader::class, $jws);
    }
}
