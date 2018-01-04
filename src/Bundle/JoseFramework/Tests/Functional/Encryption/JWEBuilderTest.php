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

use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Encryption\JWEBuilderFactory;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

/**
 * @group Bundle
 * @group Functional
 */
final class JWEBuilderTest extends WebTestCase
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
    public function theJWEBuilderFactoryIsAvailable()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        self::assertNotNull($container);
        self::assertTrue($container->has(JWEBuilderFactory::class));
    }

    /**
     * @test
     */
    public function theJWEBuilderFactoryCanCreateAJWEBuilder()
    {
        $client = static::createClient();

        /** @var JWEBuilderFactory $jweFactory */
        $jweFactory = $client->getContainer()->get(JWEBuilderFactory::class);

        $jwe = $jweFactory->create(['RSA1_5'], ['A256GCM'], ['DEF']);

        self::assertInstanceOf(JWEBuilder::class, $jwe);
    }

    /**
     * @test
     */
    public function aJWEBuilderCanBeDefinedUsingTheConfigurationFile()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        self::assertTrue($container->has('jose.jwe_builder.builder1'));

        $jwe = $container->get('jose.jwe_builder.builder1');
        self::assertInstanceOf(JWEBuilder::class, $jwe);
    }

    /**
     * @test
     */
    public function aJWEBuilderCanBeDefinedFromAnotherBundleUsingTheHelper()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        self::assertTrue($container->has('jose.jwe_builder.builder2'));

        $jwe = $container->get('jose.jwe_builder.builder2');
        self::assertInstanceOf(JWEBuilder::class, $jwe);
    }
}
