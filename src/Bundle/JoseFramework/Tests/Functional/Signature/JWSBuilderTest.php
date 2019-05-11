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

use Jose\Bundle\JoseFramework\Services\JWSBuilder;
use Jose\Component\Signature\JWSBuilderFactory;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

/**
 * @group Bundle
 * @group functional
 *
 * @internal
 * @coversNothing
 */
class JWSBuilderTest extends WebTestCase
{
    protected function setUp(): void
    {
        if (!class_exists(JWSBuilderFactory::class)) {
            static::markTestSkipped('The component "web-token/jwt-signature" is not installed.');
        }
    }

    /**
     * @test
     */
    public function jWSBuilderFactoryIsAvailable()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertNotNull($container);
        static::assertTrue($container->has(\Jose\Bundle\JoseFramework\Services\JWSBuilderFactory::class));
    }

    /**
     * @test
     */
    public function jWSBuilderFactoryCanCreateAJWSBuilder()
    {
        $client = static::createClient();

        /** @var JWSBuilderFactory $jwsFactory */
        $jwsFactory = $client->getContainer()->get(\Jose\Bundle\JoseFramework\Services\JWSBuilderFactory::class);

        $jws = $jwsFactory->create(['none']);

        static::assertInstanceOf(JWSBuilder::class, $jws);
    }

    /**
     * @test
     */
    public function jWSBuilderFromConfigurationIsAvailable()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertTrue($container->has('jose.jws_builder.builder1'));

        $jws = $container->get('jose.jws_builder.builder1');
        static::assertInstanceOf(JWSBuilder::class, $jws);
    }

    /**
     * @test
     */
    public function jWSBuilderFromExternalBundleExtensionIsAvailable()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertTrue($container->has('jose.jws_builder.builder2'));

        $jws = $container->get('jose.jws_builder.builder2');
        static::assertInstanceOf(JWSBuilder::class, $jws);
    }
}
