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

namespace Jose\Bundle\KeyManagement\Tests;

use Jose\Component\Core\JWK;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

/**
 * @group Bundle
 * @group Functional
 * @group KeyManagement
 */
final class JWKLoaderTest extends WebTestCase
{
    /**
     * @test
     */
    public function aJWKCanBeDefinedInTheConfiguration()
    {
        $client = static::createClient();

        $container = $client->getContainer();
        self::assertTrue($container->has('jose.key.jwk1'));
        self::assertInstanceOf(JWK::class, $container->get('jose.key.jwk1'));
    }

    /**
     * @test
     */
    public function aJWKCanBeDefinedFromAnotherBundle()
    {
        $client = static::createClient();

        $container = $client->getContainer();
        self::assertTrue($container->has('jose.key.jwk2'));
        self::assertInstanceOf(JWK::class, $container->get('jose.key.jwk2'));
    }

    /**
     * @test
     */
    public function aX509InFileCanBeDefinedInTheConfiguration()
    {
        $client = static::createClient();

        $container = $client->getContainer();
        self::assertTrue($container->has('jose.key.certificate1'));
        self::assertInstanceOf(JWK::class, $container->get('jose.key.certificate1'));
    }

    /**
     * @test
     */
    public function aDirectX509InputCanBeDefinedInTheConfiguration()
    {
        $client = static::createClient();

        $container = $client->getContainer();
        self::assertTrue($container->has('jose.key.x5c1'));
        self::assertInstanceOf(JWK::class, $container->get('jose.key.x5c1'));
    }

    /**
     * @test
     */
    public function anEncryptedKeyFileCanBeLoadedInTheConfiguration()
    {
        $client = static::createClient();

        $container = $client->getContainer();
        self::assertTrue($container->has('jose.key.file1'));
        self::assertInstanceOf(JWK::class, $container->get('jose.key.file1'));
    }

    /**
     * @test
     */
    public function aJWKCanBeLoadedFromAJwkSetInTheConfiguration()
    {
        $client = static::createClient();

        $container = $client->getContainer();
        self::assertTrue($container->has('jose.key.jwkset1'));
        self::assertInstanceOf(JWK::class, $container->get('jose.key.jwkset1'));
    }
}
