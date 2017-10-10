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

use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Encryption\JWEBuilderFactory;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

/**
 * @group Bundle
 * @group Functional
 */
final class JWEBuilderTest extends WebTestCase
{
    public function testJWEBuilderFactoryIsAvailable()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        self::assertNotNull($container);
        self::assertTrue($container->has(JWEBuilderFactory::class));
    }

    public function testJWEBuilderFactoryCanCreateAJWEBuilder()
    {
        $client = static::createClient();

        /** @var JWEBuilderFactory $jweFactory */
        $jweFactory = $client->getContainer()->get(JWEBuilderFactory::class);

        $jwe = $jweFactory->create(['RSA1_5'], ['A256GCM'], ['DEF']);

        self::assertInstanceOf(JWEBuilder::class, $jwe);
    }

    public function testJWEBuilderFromConfigurationIsAvailable()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        self::assertTrue($container->has('jose.jwe_builder.builder1'));

        $jwe = $container->get('jose.jwe_builder.builder1');
        self::assertInstanceOf(JWEBuilder::class, $jwe);
    }

    public function testJWEBuilderFromExternalBundleExtensionIsAvailable()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        self::assertTrue($container->has('jose.jwe_builder.builder2'));

        $jwe = $container->get('jose.jwe_builder.builder2');
        self::assertInstanceOf(JWEBuilder::class, $jwe);
    }
}
