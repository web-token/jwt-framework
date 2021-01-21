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

namespace Jose\Tests\Bundle\JoseFramework\Functional\Serializer;

use Jose\Bundle\JoseFramework\Serializer\JWSEncoder;
use Jose\Bundle\JoseFramework\Services\JWSBuilderFactory;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\JWSBuilderFactory as BaseJWSBuilderFactory;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use Jose\Component\Signature\Serializer\JWSSerializerManagerFactory;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\Serializer\Serializer;

/**
 * @group Bundle
 * @group functional
 *
 * @internal
 */
final class JWSEncoderTest extends WebTestCase
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
    public function jWSEncoderIsAvailable(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertInstanceOf(ContainerInterface::class, $container);
        /** @var Serializer $serializer */
        $serializer = $container->get('serializer');
        static::assertTrue($serializer->supportsEncoding('jws_compact'));
        static::assertTrue($serializer->supportsEncoding('jws_json_flattened'));
        static::assertTrue($serializer->supportsEncoding('jws_json_general'));
        static::assertTrue($serializer->supportsDecoding('jws_compact'));
        static::assertTrue($serializer->supportsDecoding('jws_json_flattened'));
        static::assertTrue($serializer->supportsDecoding('jws_json_general'));
    }

    /**
     * @test
     */
    public function jWSEncoderSupportsAllFormatsByDefault(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertInstanceOf(ContainerInterface::class, $container);
        $jwsSerializerManagerFactory = $container->get(JWSSerializerManagerFactory::class);
        static::assertInstanceOf(JWSSerializerManagerFactory::class, $jwsSerializerManagerFactory);
        $serializer = new JWSEncoder($jwsSerializerManagerFactory);
        static::assertTrue($serializer->supportsEncoding('jws_compact'));
        static::assertTrue($serializer->supportsEncoding('jws_json_flattened'));
        static::assertTrue($serializer->supportsEncoding('jws_json_general'));
        static::assertTrue($serializer->supportsDecoding('jws_compact'));
        static::assertTrue($serializer->supportsDecoding('jws_json_flattened'));
        static::assertTrue($serializer->supportsDecoding('jws_json_general'));
    }

    /**
     * @test
     */
    public function jWSEncoderCanEncodeAllFormats(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertInstanceOf(ContainerInterface::class, $container);
        $jwsSerializerManagerFactory = $container->get(JWSSerializerManagerFactory::class);
        static::assertInstanceOf(JWSSerializerManagerFactory::class, $jwsSerializerManagerFactory);
        $serializer = new JWSEncoder($jwsSerializerManagerFactory);
        /** @var JWSBuilderFactory $jwsFactory */
        $jwsFactory = $container->get(JWSBuilderFactory::class);
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
        static::assertEquals('eyJhbGciOiJIUzI1NiJ9.SGVsbG8gV29ybGQh.qTzr2HflJbt-MDo1Ye7i5W85avH4hrhvb1U6tbd_mzY', $serializer->encode($jws, 'jws_compact'));
        static::assertEquals('{"payload":"SGVsbG8gV29ybGQh","protected":"eyJhbGciOiJIUzI1NiJ9","signature":"qTzr2HflJbt-MDo1Ye7i5W85avH4hrhvb1U6tbd_mzY"}', $serializer->encode($jws, 'jws_json_flattened'));
        static::assertEquals('{"payload":"SGVsbG8gV29ybGQh","signatures":[{"signature":"qTzr2HflJbt-MDo1Ye7i5W85avH4hrhvb1U6tbd_mzY","protected":"eyJhbGciOiJIUzI1NiJ9"}]}', $serializer->encode($jws, 'jws_json_general'));
    }

    /**
     * @test
     */
    public function jWSEncoderCanDecodeAllFormats(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertInstanceOf(ContainerInterface::class, $container);
        $jwsSerializerManagerFactory = $container->get(JWSSerializerManagerFactory::class);
        static::assertInstanceOf(JWSSerializerManagerFactory::class, $jwsSerializerManagerFactory);
        $serializer = new JWSEncoder($jwsSerializerManagerFactory);
        /** @var JWSBuilderFactory $jwsFactory */
        $jwsFactory = $container->get(JWSBuilderFactory::class);
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
        static::assertEquals($jws, $serializer->decode('eyJhbGciOiJIUzI1NiJ9.SGVsbG8gV29ybGQh.qTzr2HflJbt-MDo1Ye7i5W85avH4hrhvb1U6tbd_mzY', 'jws_compact'));
        static::assertEquals($jws, $serializer->decode('{"payload":"SGVsbG8gV29ybGQh","protected":"eyJhbGciOiJIUzI1NiJ9","signature":"qTzr2HflJbt-MDo1Ye7i5W85avH4hrhvb1U6tbd_mzY"}', 'jws_json_flattened'));
        static::assertEquals($jws, $serializer->decode('{"payload":"SGVsbG8gV29ybGQh","signatures":[{"signature":"qTzr2HflJbt-MDo1Ye7i5W85avH4hrhvb1U6tbd_mzY","protected":"eyJhbGciOiJIUzI1NiJ9"}]}', 'jws_json_general'));
    }

    /**
     * @test
     */
    public function jWSEncoderSupportsEncodingWithSpecificSignature(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertInstanceOf(ContainerInterface::class, $container);
        $jwsSerializerManagerFactory = $container->get(JWSSerializerManagerFactory::class);
        static::assertInstanceOf(JWSSerializerManagerFactory::class, $jwsSerializerManagerFactory);
        $serializer = new JWSEncoder($jwsSerializerManagerFactory);
        /** @var JWSBuilderFactory $jwsFactory */
        $jwsFactory = $container->get(JWSBuilderFactory::class);
        $builder = $jwsFactory->create(['HS256']);
        $jwk = new JWK([
            'kty' => 'oct',
            'k' => '3pWc2vAZpHoV7XmCT-z2hWhdQquwQwW5a3XTojbf87c',
        ]);
        $jwk2 = new JWK([
            'kty' => 'oct',
            'k' => '45d2aGyfduzrkcmL7duvUTDTlXS2s3u4uMER2feQruU',
        ]);
        $jws = $builder
            ->create()
            ->withPayload('Hello World!')
            ->addSignature($jwk, [
                'alg' => 'HS256',
            ])
            ->addSignature($jwk2, [
                'alg' => 'HS256',
            ])
            ->build()
        ;
        $context = [
            'signature_index' => 0,
        ];
        $context2 = [
            'signature_index' => 1,
        ];
        // No context, signature index = 0
        static::assertEquals('eyJhbGciOiJIUzI1NiJ9.SGVsbG8gV29ybGQh.qTzr2HflJbt-MDo1Ye7i5W85avH4hrhvb1U6tbd_mzY', $serializer->encode($jws, 'jws_compact'));
        static::assertEquals('{"payload":"SGVsbG8gV29ybGQh","protected":"eyJhbGciOiJIUzI1NiJ9","signature":"qTzr2HflJbt-MDo1Ye7i5W85avH4hrhvb1U6tbd_mzY"}', $serializer->encode($jws, 'jws_json_flattened'));
        static::assertEquals('{"payload":"SGVsbG8gV29ybGQh","signatures":[{"signature":"qTzr2HflJbt-MDo1Ye7i5W85avH4hrhvb1U6tbd_mzY","protected":"eyJhbGciOiJIUzI1NiJ9"},{"signature":"ZIKPsa3NtNoACjvh6fhfg6PZgmKiuss_9sDPtMZxtNU","protected":"eyJhbGciOiJIUzI1NiJ9"}]}', $serializer->encode($jws, 'jws_json_general'));
        // With context, signature index = 0
        static::assertEquals('eyJhbGciOiJIUzI1NiJ9.SGVsbG8gV29ybGQh.qTzr2HflJbt-MDo1Ye7i5W85avH4hrhvb1U6tbd_mzY', $serializer->encode($jws, 'jws_compact', $context));
        static::assertEquals('{"payload":"SGVsbG8gV29ybGQh","protected":"eyJhbGciOiJIUzI1NiJ9","signature":"qTzr2HflJbt-MDo1Ye7i5W85avH4hrhvb1U6tbd_mzY"}', $serializer->encode($jws, 'jws_json_flattened', $context));
        static::assertEquals('{"payload":"SGVsbG8gV29ybGQh","signatures":[{"signature":"qTzr2HflJbt-MDo1Ye7i5W85avH4hrhvb1U6tbd_mzY","protected":"eyJhbGciOiJIUzI1NiJ9"},{"signature":"ZIKPsa3NtNoACjvh6fhfg6PZgmKiuss_9sDPtMZxtNU","protected":"eyJhbGciOiJIUzI1NiJ9"}]}', $serializer->encode($jws, 'jws_json_general', $context));
        // With context, signature index = 1
        static::assertEquals('eyJhbGciOiJIUzI1NiJ9.SGVsbG8gV29ybGQh.ZIKPsa3NtNoACjvh6fhfg6PZgmKiuss_9sDPtMZxtNU', $serializer->encode($jws, 'jws_compact', $context2));
        static::assertEquals('{"payload":"SGVsbG8gV29ybGQh","protected":"eyJhbGciOiJIUzI1NiJ9","signature":"ZIKPsa3NtNoACjvh6fhfg6PZgmKiuss_9sDPtMZxtNU"}', $serializer->encode($jws, 'jws_json_flattened', $context2));
        static::assertEquals('{"payload":"SGVsbG8gV29ybGQh","signatures":[{"signature":"qTzr2HflJbt-MDo1Ye7i5W85avH4hrhvb1U6tbd_mzY","protected":"eyJhbGciOiJIUzI1NiJ9"},{"signature":"ZIKPsa3NtNoACjvh6fhfg6PZgmKiuss_9sDPtMZxtNU","protected":"eyJhbGciOiJIUzI1NiJ9"}]}', $serializer->encode($jws, 'jws_json_general', $context2));
    }

    /**
     * @test
     */
    public function jWSEncoderSupportsCustomSerializerManager(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertInstanceOf(ContainerInterface::class, $container);
        $jwsSerializerManager = new JWSSerializerManager([
            new CompactSerializer(),
        ]);
        $jwsSerializerManagerFactory = $container->get(JWSSerializerManagerFactory::class);
        static::assertInstanceOf(JWSSerializerManagerFactory::class, $jwsSerializerManagerFactory);
        $serializer = new JWSEncoder($jwsSerializerManagerFactory, $jwsSerializerManager);
        /** @var JWSBuilderFactory $jwsFactory */
        $jwsFactory = $container->get(JWSBuilderFactory::class);
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
        static::assertTrue($serializer->supportsEncoding('jws_compact'));
        static::assertFalse($serializer->supportsEncoding('jws_json_flattened'));
        static::assertFalse($serializer->supportsEncoding('jws_json_general'));
        static::assertTrue($serializer->supportsDecoding('jws_compact'));
        static::assertFalse($serializer->supportsDecoding('jws_json_flattened'));
        static::assertFalse($serializer->supportsDecoding('jws_json_general'));
        static::assertEquals('eyJhbGciOiJIUzI1NiJ9.SGVsbG8gV29ybGQh.qTzr2HflJbt-MDo1Ye7i5W85avH4hrhvb1U6tbd_mzY', $serializer->encode($jws, 'jws_compact'));
        static::assertEquals($jws, $serializer->decode('eyJhbGciOiJIUzI1NiJ9.SGVsbG8gV29ybGQh.qTzr2HflJbt-MDo1Ye7i5W85avH4hrhvb1U6tbd_mzY', 'jws_compact'));
    }

    /**
     * @test
     */
    public function jWSEncoderShouldThrowOnUnsupportedFormatWhenEncoding(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertInstanceOf(ContainerInterface::class, $container);
        $serializerManager = new JWSSerializerManager([
            new CompactSerializer(),
        ]);
        $jwsSerializerManagerFactory = $container->get(JWSSerializerManagerFactory::class);
        static::assertInstanceOf(JWSSerializerManagerFactory::class, $jwsSerializerManagerFactory);
        $serializer = new JWSEncoder($jwsSerializerManagerFactory, $serializerManager);
        /** @var JWSBuilderFactory $jwsFactory */
        $jwsFactory = $container->get(JWSBuilderFactory::class);
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
        static::assertEquals('eyJhbGciOiJIUzI1NiJ9.SGVsbG8gV29ybGQh.qTzr2HflJbt-MDo1Ye7i5W85avH4hrhvb1U6tbd_mzY', $serializer->encode($jws, 'jws_compact'));
        $this->expectExceptionMessage('Cannot encode JWS to jws_json_flattened format.');
        $serializer->encode($jws, 'jws_json_flattened');
    }

    /**
     * @test
     */
    public function jWSEncoderShouldThrowOnUnsupportedFormatWhenDecoding(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertInstanceOf(ContainerInterface::class, $container);
        $serializerManager = new JWSSerializerManager([
            new CompactSerializer(),
        ]);
        $jwsSerializerManagerFactory = $container->get(JWSSerializerManagerFactory::class);
        static::assertInstanceOf(JWSSerializerManagerFactory::class, $jwsSerializerManagerFactory);
        $serializer = new JWSEncoder($jwsSerializerManagerFactory, $serializerManager);
        /** @var JWSBuilderFactory $jwsFactory */
        $jwsFactory = $container->get(JWSBuilderFactory::class);
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
        static::assertEquals($jws, $serializer->decode('eyJhbGciOiJIUzI1NiJ9.SGVsbG8gV29ybGQh.qTzr2HflJbt-MDo1Ye7i5W85avH4hrhvb1U6tbd_mzY', 'jws_compact'));
        $this->expectExceptionMessage('Cannot decode JWS from jws_json_flattened format.');
        $serializer->decode('{"payload":"SGVsbG8gV29ybGQh","protected":"eyJhbGciOiJIUzI1NiJ9","signature":"qTzr2HflJbt-MDo1Ye7i5W85avH4hrhvb1U6tbd_mzY"}', 'jws_json_flattened');
    }
}
