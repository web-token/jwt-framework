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

namespace Jose\Bundle\JoseFramework\Tests\Functional\Encryption;

use Jose\Bundle\JoseFramework\Services\JWELoaderFactory as JWELoaderFactoryAlias;
use Jose\Component\Encryption\JWEBuilderFactory;
use Jose\Component\Encryption\JWELoader;
use Jose\Component\Encryption\JWELoaderFactory;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

/**
 * @group Bundle
 * @group functional
 *
 * @internal
 */
class JWELoaderTest extends WebTestCase
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
    public function theJWELoaderFactoryIsAvailable()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertNotNull($container);
        static::assertTrue($container->has(JWELoaderFactoryAlias::class));
    }

    /**
     * @test
     */
    public function theWELoaderFactoryCanCreateAJWELoader()
    {
        $client = static::createClient();

        /** @var JWELoaderFactory $jweLoaderFactory */
        $jweLoaderFactory = $client->getContainer()->get(JWELoaderFactoryAlias::class);

        $jwe = $jweLoaderFactory->create(['jwe_compact'], ['RSA1_5'], ['A256GCM'], ['DEF']);

        static::assertInstanceOf(JWELoader::class, $jwe);
        static::assertEquals(['jwe_compact'], $jwe->getSerializerManager()->names());
        static::assertEquals(['RSA1_5'], $jwe->getJweDecrypter()->getKeyEncryptionAlgorithmManager()->list());
        static::assertEquals(['A256GCM'], $jwe->getJweDecrypter()->getContentEncryptionAlgorithmManager()->list());
        static::assertEquals(['DEF'], $jwe->getJweDecrypter()->getCompressionMethodManager()->list());
    }

    /**
     * @test
     */
    public function aJWELoaderCanBeDefinedUsingTheConfigurationFile()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertTrue($container->has('jose.jwe_loader.jwe_loader1'));

        $jwe = $container->get('jose.jwe_loader.jwe_loader1');
        static::assertInstanceOf(JWELoader::class, $jwe);
    }

    /**
     * @test
     */
    public function aJWELoaderCanBeDefinedFromAnotherBundleUsingTheHelper()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertTrue($container->has('jose.jwe_loader.jwe_loader2'));

        $jwe = $container->get('jose.jwe_loader.jwe_loader2');
        static::assertInstanceOf(JWELoader::class, $jwe);
    }
}
