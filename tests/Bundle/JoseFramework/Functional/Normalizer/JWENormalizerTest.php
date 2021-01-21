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

use Jose\Bundle\JoseFramework\Normalizer\JWENormalizer;
use Jose\Bundle\JoseFramework\Services\JWEBuilderFactory;
use Jose\Component\Core\JWK;
use Jose\Component\Encryption\JWE;
use Jose\Component\Encryption\JWEBuilderFactory as BaseJWEBuilderFactory;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\Serializer\Serializer;

/**
 * @group Bundle
 * @group functional
 *
 * @internal
 */
final class JWENormalizerTest extends WebTestCase
{
    protected function setUp(): void
    {
        if (!class_exists(BaseJWEBuilderFactory::class)) {
            static::markTestSkipped('The component "web-token/jwt-encryption" is not installed.');
        }
        if (!class_exists(Serializer::class)) {
            static::markTestSkipped('The component "symfony/serializer" is not installed.');
        }
    }

    /**
     * @test
     */
    public function jWENormalizerIsAvailable(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertInstanceOf(ContainerInterface::class, $container);
        $serializer = $container->get('serializer');
        static::assertInstanceOf(Serializer::class, $serializer);
        $jweFactory = $container->get(JWEBuilderFactory::class);
        static::assertInstanceOf(JWEBuilderFactory::class, $jweFactory);
        $builder = $jweFactory->create(['A256KW'], ['A256CBC-HS512'], []);
        $jwk = new JWK([
            'kty' => 'oct',
            'k' => '3pWc2vAZpHoV7XmCT-z2hWhdQquwQwW5a3XTojbf87c',
        ]);
        $jwe = $builder
            ->create()
            ->withPayload('Hello World!')
            ->withSharedProtectedHeader([
                'alg' => 'A256KW',
                'enc' => 'A256CBC-HS512',
            ])
            ->addRecipient($jwk)
            ->build()
        ;
        static::assertTrue($serializer->supportsNormalization($jwe));
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
        $serializer = new JWENormalizer();
        $jweFactory = $container->get(JWEBuilderFactory::class);
        static::assertInstanceOf(JWEBuilderFactory::class, $jweFactory);
        $builder = $jweFactory->create(['A256KW'], ['A256CBC-HS512'], []);
        $jwk = new JWK([
            'kty' => 'oct',
            'k' => '3pWc2vAZpHoV7XmCT-z2hWhdQquwQwW5a3XTojbf87c',
        ]);
        $jwe = $builder
            ->create()
            ->withPayload('Hello World!')
            ->withSharedProtectedHeader([
                'alg' => 'A256KW',
                'enc' => 'A256CBC-HS512',
            ])
            ->addRecipient($jwk)
            ->build()
        ;
        static::assertTrue($serializer->supportsNormalization($jwe));
        static::assertEquals($jwe, $serializer->normalize($jwe));
        static::assertEquals($jwe, $serializer->denormalize($jwe, JWE::class));
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
        static::assertInstanceOf(Serializer::class, $serializer);
        $jweFactory = $container->get(JWEBuilderFactory::class);
        static::assertInstanceOf(JWEBuilderFactory::class, $jweFactory);
        $builder = $jweFactory->create(['A256KW'], ['A256CBC-HS512'], []);
        $jwk = new JWK([
            'kty' => 'oct',
            'k' => '3pWc2vAZpHoV7XmCT-z2hWhdQquwQwW5a3XTojbf87c',
        ]);
        $jwe = $builder
            ->create()
            ->withPayload('Hello World!')
            ->withSharedProtectedHeader([
                'alg' => 'A256KW',
                'enc' => 'A256CBC-HS512',
            ])
            ->addRecipient($jwk)
            ->build()
        ;
        static::assertTrue($serializer->supportsNormalization($jwe));
        static::assertEquals($jwe, $serializer->normalize($jwe));
        static::assertEquals($jwe, $serializer->denormalize($jwe, JWE::class));
    }
}
