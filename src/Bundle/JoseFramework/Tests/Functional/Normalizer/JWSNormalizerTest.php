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

namespace Jose\Bundle\JoseFramework\Tests\Functional\Normalizer;

use Jose\Bundle\JoseFramework\Normalizer\JWSNormalizer;
use Jose\Bundle\JoseFramework\Services\JWSBuilderFactory;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSBuilderFactory as BaseJWSBuilderFactory;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\Serializer\Serializer;

/**
 * @group Bundle
 * @group functional
 *
 * @internal
 * @coversNothing
 */
final class JWSNormalizerTest extends WebTestCase
{
    protected function setUp(): void
    {
        if (!class_exists(BaseJWSBuilderFactory::class)) {
            static::markTestSkipped('The component "web-token/jwt-signature" is not installed.');
        }
        if (!class_exists(Serializer::class)) {
            static::markTestSkipped('The component "symfony/serializer" is not installed.');
        }
    }

    /**
     * @test
     */
    public function jWSNormalizerIsAvailable()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        /** @var Serializer $serializer */
        $serializer = $container->get('serializer');
        /** @var JWSBuilderFactory $jwsFactory */
        $jwsFactory = $client->getContainer()->get(JWSBuilderFactory::class);
        $builder = $jwsFactory->create(['HS256']);
        $jwk = new JWK([
            'kty' => 'oct',
            'k' => '3pWc2vAZpHoV7XmCT-z2hWhdQquwQwW5a3XTojbf87c',
        ]);
        $jws = $builder
            ->create()
            ->withPayload('Hello World!')
            ->addSignature($jwk, [
                'alg' => 'HS256',
            ])
            ->build()
        ;
        static::assertInstanceOf(JWS::class, $jws);
        static::assertTrue($serializer->supportsNormalization($jws));
    }

    /**
     * @test
     */
    public function jWSNormalizerPassesThrough()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        $serializer = new JWSNormalizer();
        /** @var JWSBuilderFactory $jwsFactory */
        $jwsFactory = $client->getContainer()->get(JWSBuilderFactory::class);
        $builder = $jwsFactory->create(['HS256']);
        $jwk = new JWK([
            'kty' => 'oct',
            'k' => '3pWc2vAZpHoV7XmCT-z2hWhdQquwQwW5a3XTojbf87c',
        ]);
        $jws = $builder
            ->create()
            ->withPayload('Hello World!')
            ->addSignature($jwk, [
                'alg' => 'HS256',
            ])
            ->build()
        ;
        static::assertInstanceOf(JWS::class, $jws);
        static::assertTrue($serializer->supportsNormalization($jws));
        static::assertEquals($jws, $serializer->normalize($jws));
        static::assertEquals($jws, $serializer->denormalize($jws, JWS::class));
    }

    /**
     * @test
     */
    public function jWSNormalizerFromContainerPassesThrough()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        /** @var Serializer $serializer */
        $serializer = $container->get('serializer');
        /** @var JWSBuilderFactory $jwsFactory */
        $jwsFactory = $client->getContainer()->get(JWSBuilderFactory::class);
        $builder = $jwsFactory->create(['HS256']);
        $jwk = new JWK([
            'kty' => 'oct',
            'k' => '3pWc2vAZpHoV7XmCT-z2hWhdQquwQwW5a3XTojbf87c',
        ]);
        $jws = $builder
            ->create()
            ->withPayload('Hello World!')
            ->addSignature($jwk, [
                'alg' => 'HS256',
            ])
            ->build()
        ;
        static::assertInstanceOf(JWS::class, $jws);
        static::assertTrue($serializer->supportsNormalization($jws));
        static::assertEquals($jws, $serializer->normalize($jws));
        static::assertEquals($jws, $serializer->denormalize($jws, JWS::class));
    }
}
