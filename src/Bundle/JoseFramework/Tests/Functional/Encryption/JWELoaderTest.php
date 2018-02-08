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

namespace Jose\Bundle\JoseFramework\Tests\Functional\Encryption;

use Jose\Component\Encryption\JWEBuilderFactory;
use Jose\Component\Encryption\JWELoader;
use Jose\Component\Encryption\JWELoaderFactory;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

/**
 * @group Bundle
 * @group Functional
 */
class JWELoaderTest extends WebTestCase
{
    /**
     * {@inheritdoc}
     */
    protected function setUp()
    {
        if (!class_exists(JWEBuilderFactory::class)) {
            $this->markTestSkipped('The component "web-token/jwt-encryption" is not installed.');
        }
    }

    /**
     * @test
     */
    public function theJWELoaderFactoryIsAvailable()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        self::assertNotNull($container);
        self::assertTrue($container->has(JWELoaderFactory::class));
    }

    /**
     * @test
     */
    public function theWELoaderFactoryCanCreateAJWELoader()
    {
        $client = static::createClient();

        /** @var JWELoaderFactory $jweLoaderFactory */
        $jweLoaderFactory = $client->getContainer()->get(JWELoaderFactory::class);

        $jwe = $jweLoaderFactory->create(['jwe_compact'], ['RSA1_5'], ['A256GCM'], ['DEF']);

        self::assertInstanceOf(JWELoader::class, $jwe);
        self::assertEquals(['jwe_compact'], $jwe->getSerializerManager()->list());
        self::assertEquals(['RSA1_5'], $jwe->getJweDecrypter()->getKeyEncryptionAlgorithmManager()->list());
        self::assertEquals(['A256GCM'], $jwe->getJweDecrypter()->getContentEncryptionAlgorithmManager()->list());
        self::assertEquals(['DEF'], $jwe->getJweDecrypter()->getCompressionMethodManager()->list());
    }

    /**
     * @test
     */
    public function aJWELoaderCanBeDefinedUsingTheConfigurationFile()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        self::assertTrue($container->has('jose.jwe_loader.jwe_loader1'));

        $jwe = $container->get('jose.jwe_loader.jwe_loader1');
        self::assertInstanceOf(JWELoader::class, $jwe);
    }

    /**
     * @test
     */
    public function aJWELoaderCanBeDefinedFromAnotherBundleUsingTheHelper()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        self::assertTrue($container->has('jose.jwe_loader.jwe_loader2'));

        $jwe = $container->get('jose.jwe_loader.jwe_loader2');
        self::assertInstanceOf(JWELoader::class, $jwe);
    }
}
