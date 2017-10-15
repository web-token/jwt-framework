<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Bundle\Encryption\Tests;

use Jose\Component\Encryption\JWELoader;
use Jose\Component\Encryption\JWELoaderFactory;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

/**
 * @group Bundle
 * @group Functional
 */
final class JWELoaderTest extends WebTestCase
{
    public function testJWELoaderFactoryIsAvailable()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        self::assertNotNull($container);
        self::assertTrue($container->has(JWELoaderFactory::class));
    }

    public function testJWELoaderFactoryCanCreateAJWELoader()
    {
        $client = static::createClient();

        /** @var JWELoaderFactory $jweFactory */
        $jweFactory = $client->getContainer()->get(JWELoaderFactory::class);

        $jwe = $jweFactory->create(['RSA1_5'], ['A256GCM'], ['DEF'], [], ['jwe_compact', 'jwe_json_general', 'jwe_json_flattened']);

        self::assertInstanceOf(JWELoader::class, $jwe);
    }

    public function testJWELoaderFromConfigurationIsAvailable()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        self::assertTrue($container->has('jose.jwe_loader.loader1'));

        $jwe = $container->get('jose.jwe_loader.loader1');
        self::assertInstanceOf(JWELoader::class, $jwe);
    }

    public function testJWELoaderFromExternalBundleExtensionIsAvailable()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        self::assertTrue($container->has('jose.jwe_loader.loader2'));

        $jwe = $container->get('jose.jwe_loader.loader2');
        self::assertInstanceOf(JWELoader::class, $jwe);
    }
}
