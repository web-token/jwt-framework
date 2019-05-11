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

use Jose\Bundle\JoseFramework\Normalizer\JWENormalizer;
use Jose\Bundle\JoseFramework\Services\JWEBuilderFactory;
use Jose\Component\Core\JWK;
use Jose\Component\Encryption\JWE;
use Jose\Component\Encryption\JWEBuilderFactory as BaseJWEBuilderFactory;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\Serializer\Serializer;

/**
 * @group Bundle
 * @group functional
 *
 * @internal
 * @coversNothing
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
    public function jWENormalizerIsAvailable()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        /** @var Serializer $serializer */
        $serializer = $container->get('serializer');
        /** @var JWEBuilderFactory $jweFactory */
        $jweFactory = $client->getContainer()->get(JWEBuilderFactory::class);
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
        static::assertInstanceOf(JWE::class, $jwe);
        static::assertTrue($serializer->supportsNormalization($jwe));
    }

    /**
     * @test
     */
    public function jWSNormalizerPassesThrough()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        $serializer = new JWENormalizer();
        /** @var JWEBuilderFactory $jweFactory */
        $jweFactory = $client->getContainer()->get(JWEBuilderFactory::class);
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
        static::assertInstanceOf(JWE::class, $jwe);
        static::assertTrue($serializer->supportsNormalization($jwe));
        static::assertEquals($jwe, $serializer->normalize($jwe));
        static::assertEquals($jwe, $serializer->denormalize($jwe, JWE::class));
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
        /** @var JWEBuilderFactory $jweFactory */
        $jweFactory = $client->getContainer()->get(JWEBuilderFactory::class);
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
        static::assertInstanceOf(JWE::class, $jwe);
        static::assertTrue($serializer->supportsNormalization($jwe));
        static::assertEquals($jwe, $serializer->normalize($jwe));
        static::assertEquals($jwe, $serializer->denormalize($jwe, JWE::class));
    }
}
