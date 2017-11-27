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

namespace Jose\Bundle\Signature\Tests\Signature;

use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWSBuilderFactory;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

/**
 * @group Bundle
 * @group Functional
 */
final class JWSBuilderTest extends WebTestCase
{
    public function testJWSBuilderFactoryIsAvailable()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        self::assertNotNull($container);
        self::assertTrue($container->has(JWSBuilderFactory::class));
    }

    public function testJWSBuilderFactoryCanCreateAJWSBuilder()
    {
        $client = static::createClient();

        /** @var JWSBuilderFactory $jwsFactory */
        $jwsFactory = $client->getContainer()->get(JWSBuilderFactory::class);

        $jws = $jwsFactory->create(['none']);

        self::assertInstanceOf(JWSBuilder::class, $jws);
    }

    public function testJWSBuilderFromConfigurationIsAvailable()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        self::assertTrue($container->has('jose.jws_builder.builder1'));

        $jws = $container->get('jose.jws_builder.builder1');
        self::assertInstanceOf(JWSBuilder::class, $jws);
    }

    public function testJWSBuilderFromExternalBundleExtensionIsAvailable()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        self::assertTrue($container->has('jose.jws_builder.builder2'));

        $jws = $container->get('jose.jws_builder.builder2');
        self::assertInstanceOf(JWSBuilder::class, $jws);
    }
}
