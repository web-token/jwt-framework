<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Tests\Bundle\JoseFramework\Functional\Normalizer;

use Jose\Bundle\JoseFramework\Normalizer\JWSNormalizer;
use Jose\Bundle\JoseFramework\Services\JWSBuilderFactory;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSBuilderFactory as BaseJWSBuilderFactory;
use Jose\Component\Signature\Serializer\Serializer;
use Psr\Container\ContainerInterface;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

/**
 * @group Bundle
 * @group functional
 *
 * @internal
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
    public function jWSNormalizerIsAvailable(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertInstanceOf(ContainerInterface::class, $container);
        $serializer = $container->get('serializer');
        static::assertInstanceOf(\Symfony\Component\Serializer\Serializer::class, $serializer);
        $jwsFactory = $container->get(JWSBuilderFactory::class);
        static::assertInstanceOf(JWSBuilderFactory::class, $jwsFactory);
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
        static::assertTrue($serializer->supportsNormalization($jws));
    }

    /**
     * @test
     */
    public function jWSNormalizerPassesThrough(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertInstanceOf(ContainerInterface::class, $container);
        $serializer = new JWSNormalizer();
        $jwsFactory = $container->get(JWSBuilderFactory::class);
        static::assertInstanceOf(JWSBuilderFactory::class, $jwsFactory);
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
        static::assertTrue($serializer->supportsNormalization($jws));
        static::assertEquals($jws, $serializer->normalize($jws));
        static::assertEquals($jws, $serializer->denormalize($jws, JWS::class));
    }

    /**
     * @test
     */
    public function jWSNormalizerFromContainerPassesThrough(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertInstanceOf(ContainerInterface::class, $container);
        $serializer = $container->get('serializer');
        static::assertInstanceOf(\Symfony\Component\Serializer\Serializer::class, $serializer);
        $jwsFactory = $container->get(JWSBuilderFactory::class);
        static::assertInstanceOf(JWSBuilderFactory::class, $jwsFactory);
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
        static::assertTrue($serializer->supportsNormalization($jws));
        static::assertEquals($jws, $serializer->normalize($jws));
        static::assertEquals($jws, $serializer->denormalize($jws, JWS::class));
    }
}
