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

namespace Jose\Bundle\JoseFramework\Tests\Functional\Signature;

use Jose\Component\Signature\JWSBuilderFactory;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\JWSVerifierFactory;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

/**
 * @group Bundle
 * @group Functional
 */
final class JWSLoaderTest extends WebTestCase
{
    /**
     * {@inheritdoc}
     */
    protected function setUp()
    {
        if (!class_exists(JWSBuilderFactory::class)) {
            $this->markTestSkipped('The component "web-token/jwt-signature" is not installed.');
        }
    }

    public function testJWSVerifierFactoryIsAvailable()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        self::assertNotNull($container);
        self::assertTrue($container->has(JWSVerifierFactory::class));
    }

    public function testJWSVerifierFactoryCanCreateAJWSVerifier()
    {
        $client = static::createClient();

        /** @var JWSVerifierFactory $jwsFactory */
        $jwsFactory = $client->getContainer()->get(JWSVerifierFactory::class);

        $jws = $jwsFactory->create(['none']);

        self::assertInstanceOf(JWSVerifier::class, $jws);
    }

    public function testJWSVerifierFromConfigurationIsAvailable()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        self::assertTrue($container->has('jose.jws_verifier.loader1'));

        $jws = $container->get('jose.jws_verifier.loader1');
        self::assertInstanceOf(JWSVerifier::class, $jws);
    }

    public function testJWSVerifierFromExternalBundleExtensionIsAvailable()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        self::assertTrue($container->has('jose.jws_verifier.loader2'));

        $jws = $container->get('jose.jws_verifier.loader2');
        self::assertInstanceOf(JWSVerifier::class, $jws);
    }

    public function testJWSSerializerManagerFromConfigurationIsAvailable()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        self::assertTrue($container->has('jose.jws_serializer.jws_serializer1'));

        $jws = $container->get('jose.jws_serializer.jws_serializer1');
        self::assertInstanceOf(JWSSerializerManager::class, $jws);
    }

    public function testJWSSerializerManagerFromExternalBundleExtensionIsAvailable()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        self::assertTrue($container->has('jose.jws_serializer.jws_serializer2'));

        $jws = $container->get('jose.jws_serializer.jws_serializer2');
        self::assertInstanceOf(JWSSerializerManager::class, $jws);
    }
}
