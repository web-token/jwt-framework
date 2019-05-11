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

use Jose\Bundle\JoseFramework\Services\JWEBuilder;
use Jose\Component\Encryption\JWEBuilderFactory;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

/**
 * @group Bundle
 * @group functional
 *
 * @internal
 * @coversNothing
 */
class JWEBuilderTest extends WebTestCase
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
    public function theJWEBuilderFactoryIsAvailable()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertNotNull($container);
        static::assertTrue($container->has(\Jose\Bundle\JoseFramework\Services\JWEBuilderFactory::class));
    }

    /**
     * @test
     */
    public function theJWEBuilderFactoryCanCreateAJWEBuilder()
    {
        $client = static::createClient();

        /** @var JWEBuilderFactory $jweFactory */
        $jweFactory = $client->getContainer()->get(\Jose\Bundle\JoseFramework\Services\JWEBuilderFactory::class);

        $jwe = $jweFactory->create(['RSA1_5'], ['A256GCM'], ['DEF']);

        static::assertInstanceOf(JWEBuilder::class, $jwe);
    }

    /**
     * @test
     */
    public function aJWEBuilderCanBeDefinedUsingTheConfigurationFile()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertTrue($container->has('jose.jwe_builder.builder1'));

        $jwe = $container->get('jose.jwe_builder.builder1');
        static::assertInstanceOf(JWEBuilder::class, $jwe);
    }

    /**
     * @test
     */
    public function aJWEBuilderCanBeDefinedFromAnotherBundleUsingTheHelper()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertTrue($container->has('jose.jwe_builder.builder2'));

        $jwe = $container->get('jose.jwe_builder.builder2');
        static::assertInstanceOf(JWEBuilder::class, $jwe);
    }
}
