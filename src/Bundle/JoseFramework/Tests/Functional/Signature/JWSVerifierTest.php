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

use Jose\Component\Signature\JWSBuilderFactory;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\JWSVerifierFactory;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

/**
 * @group Bundle
 * @group functional
 *
 * @internal
 * @coversNothing
 */
class JWSVerifierTest extends WebTestCase
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
    public function jWSVerifierFactoryIsAvailable()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertNotNull($container);
        static::assertTrue($container->has(\Jose\Bundle\JoseFramework\Services\JWSVerifierFactory::class));
    }

    /**
     * @test
     */
    public function jWSVerifierFactoryCanCreateAJWSVerifier()
    {
        $client = static::createClient();

        /** @var JWSVerifierFactory $jwsFactory */
        $jwsFactory = $client->getContainer()->get(\Jose\Bundle\JoseFramework\Services\JWSVerifierFactory::class);

        $jws = $jwsFactory->create(['none']);

        static::assertInstanceOf(JWSVerifier::class, $jws);
    }

    /**
     * @test
     */
    public function jWSVerifierFromConfigurationIsAvailable()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertTrue($container->has('jose.jws_verifier.loader1'));

        $jws = $container->get('jose.jws_verifier.loader1');
        static::assertInstanceOf(JWSVerifier::class, $jws);
    }

    /**
     * @test
     */
    public function jWSVerifierFromExternalBundleExtensionIsAvailable()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertTrue($container->has('jose.jws_verifier.loader2'));

        $jws = $container->get('jose.jws_verifier.loader2');
        static::assertInstanceOf(JWSVerifier::class, $jws);
    }
}
