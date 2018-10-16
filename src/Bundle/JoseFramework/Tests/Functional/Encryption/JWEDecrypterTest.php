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
use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\Encryption\JWEDecrypterFactory;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

/**
 * @group Bundle
 * @group Functional
 */
class JWEDecrypterTest extends WebTestCase
{
    protected function setUp()
    {
        if (!\class_exists(JWEBuilderFactory::class)) {
            static::markTestSkipped('The component "web-token/jwt-encryption" is not installed.');
        }
    }

    /**
     * @test
     */
    public function theJWEDecrypterFactoryIsAvailable()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertNotNull($container);
        static::assertTrue($container->has(JWEDecrypterFactory::class));
    }

    /**
     * @test
     */
    public function theWEDecrypterFactoryCanCreateAJWEDecrypter()
    {
        $client = static::createClient();

        /** @var JWEDecrypterFactory $jweFactory */
        $jweFactory = $client->getContainer()->get(JWEDecrypterFactory::class);

        $jwe = $jweFactory->create(['RSA1_5'], ['A256GCM'], ['DEF']);

        static::assertInstanceOf(JWEDecrypter::class, $jwe);
    }

    /**
     * @test
     */
    public function aJWEDecrypterCanBeDefinedUsingTheConfigurationFile()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertTrue($container->has('jose.jwe_decrypter.loader1'));

        $jwe = $container->get('jose.jwe_decrypter.loader1');
        static::assertInstanceOf(JWEDecrypter::class, $jwe);
    }

    /**
     * @test
     */
    public function aJWEDecrypterCanBeDefinedFromAnotherBundleUsingTheHelper()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertTrue($container->has('jose.jwe_decrypter.loader2'));

        $jwe = $container->get('jose.jwe_decrypter.loader2');
        static::assertInstanceOf(JWEDecrypter::class, $jwe);
    }
}
