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

namespace Jose\Bundle\Signature\Tests;

use Jose\Component\Signature\JWSLoader;
use Jose\Component\Signature\JWSLoaderFactory;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

/**
 * @group Bundle
 * @group Functional
 */
final class JWSLoaderTest extends WebTestCase
{
    public function testJWSLoaderFactoryIsAvailable()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        self::assertNotNull($container);
        self::assertTrue($container->has(JWSLoaderFactory::class));
    }

    public function testJWSLoaderFactoryCanCreateAJWSLoader()
    {
        $client = static::createClient();

        /** @var JWSLoaderFactory $jwsFactory */
        $jwsFactory = $client->getContainer()->get(JWSLoaderFactory::class);

        $jws = $jwsFactory->create(['none'], ['iat', 'exp', 'nbf'], ['jws_compact', 'jws_json_general', 'jws_json_flattened']);

        self::assertInstanceOf(JWSLoader::class, $jws);
    }

    public function testJWSLoaderFromConfigurationIsAvailable()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        self::assertTrue($container->has('jose.jws_loader.loader1'));

        $jws = $container->get('jose.jws_loader.loader1');
        self::assertInstanceOf(JWSLoader::class, $jws);
    }

    public function testJWSLoaderFromExternalBundleExtensionIsAvailable()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        self::assertTrue($container->has('jose.jws_loader.loader2'));

        $jws = $container->get('jose.jws_loader.loader2');
        self::assertInstanceOf(JWSLoader::class, $jws);
    }
}
