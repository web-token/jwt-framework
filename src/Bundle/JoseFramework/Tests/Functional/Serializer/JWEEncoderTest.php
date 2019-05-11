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

namespace Jose\Bundle\JoseFramework\Tests\Functional\Serializer;

use Jose\Bundle\JoseFramework\Serializer\JWEEncoder;
use Jose\Bundle\JoseFramework\Services\JWEBuilderFactory;
use Jose\Bundle\JoseFramework\Services\JWELoaderFactory;
use Jose\Component\Core\JWK;
use Jose\Component\Encryption\JWE;
use Jose\Component\Encryption\JWEBuilderFactory as BaseJWEBuilderFactory;
use Jose\Component\Encryption\Serializer\CompactSerializer;
use Jose\Component\Encryption\Serializer\JWESerializerManager;
use Jose\Component\Encryption\Serializer\JWESerializerManagerFactory;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\Serializer\Serializer;

/**
 * @group Bundle
 * @group functional
 *
 * @internal
 * @coversNothing
 */
final class JWEEncoderTest extends WebTestCase
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
    public function jWEEncoderIsAvailable()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        /** @var Serializer $serializer */
        $serializer = $container->get('serializer');
        static::assertTrue($serializer->supportsEncoding('jwe_compact'));
        static::assertTrue($serializer->supportsEncoding('jwe_json_flattened'));
        static::assertTrue($serializer->supportsEncoding('jwe_json_general'));
        static::assertTrue($serializer->supportsDecoding('jwe_compact'));
        static::assertTrue($serializer->supportsDecoding('jwe_json_flattened'));
        static::assertTrue($serializer->supportsDecoding('jwe_json_general'));
    }

    /**
     * @test
     */
    public function jWEEncoderSupportsAllFormatsByDefault()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        $serializer = new JWEEncoder($container->get(JWESerializerManagerFactory::class));
        static::assertTrue($serializer->supportsEncoding('jwe_compact'));
        static::assertTrue($serializer->supportsEncoding('jwe_json_flattened'));
        static::assertTrue($serializer->supportsEncoding('jwe_json_general'));
        static::assertTrue($serializer->supportsDecoding('jwe_compact'));
        static::assertTrue($serializer->supportsDecoding('jwe_json_flattened'));
        static::assertTrue($serializer->supportsDecoding('jwe_json_general'));
    }

    /**
     * @test
     */
    public function jWEEncoderCanEncodeAllFormats()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        $serializer = new JWEEncoder($container->get(JWESerializerManagerFactory::class));
        /** @var JWEBuilderFactory $jweFactory */
        $jweFactory = $container->get(JWEBuilderFactory::class);
        $builder = $jweFactory->create(['A256KW'], ['A256CBC-HS512'], []);
        /** @var JWELoaderFactory $jweLoaderFactory */
        $jweLoaderFactory = $container->get(JWELoaderFactory::class);
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
        // Compact
        $loader = $jweLoaderFactory->create(['jwe_compact'], ['A256KW'], ['A256CBC-HS512'], []);
        $token = $serializer->encode($jwe, 'jwe_compact');
        static::assertRegExp('/(eyJhbGciOiJBMjU2S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0)\.(.+?)\.(.+?)\.(.+?)\.(.+)/', $token);
        static::assertInstanceOf(JWE::class, $loader->loadAndDecryptWithKey($token, $jwk, $recipient));
        // Flat
        $loader = $jweLoaderFactory->create(['jwe_json_flattened'], ['A256KW'], ['A256CBC-HS512'], []);
        $token = $serializer->encode($jwe, 'jwe_json_flattened');
        static::assertJson($token);
        static::assertInstanceOf(JWE::class, $loader->loadAndDecryptWithKey($token, $jwk, $recipient));
        // JSON
        $loader = $jweLoaderFactory->create(['jwe_json_general'], ['A256KW'], ['A256CBC-HS512'], []);
        $token = $serializer->encode($jwe, 'jwe_json_general');
        static::assertJson($token);
        static::assertInstanceOf(JWE::class, $loader->loadAndDecryptWithKey($token, $jwk, $recipient));
    }

    /**
     * @test
     */
    public function jWEEncoderCanDecodeAllFormats()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        $serializer = new JWEEncoder($container->get(JWESerializerManagerFactory::class));
        /** @var JWEBuilderFactory $jweFactory */
        $jweFactory = $container->get(JWEBuilderFactory::class);
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
        static::assertInstanceOf(JWE::class, $serializer->decode($this->serializeJWE($jwe, 'jwe_compact', 0), 'jwe_compact'));
        static::assertInstanceOf(JWE::class, $serializer->decode($this->serializeJWE($jwe, 'jwe_json_flattened', 0), 'jwe_json_flattened'));
        static::assertInstanceOf(JWE::class, $serializer->decode($this->serializeJWE($jwe, 'jwe_json_general', 0), 'jwe_json_general'));
    }

    /**
     * @test
     */
    public function jWEEncoderSupportsEncodingWithSpecificSignature()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        $serializer = new JWEEncoder($container->get(JWESerializerManagerFactory::class));
        /** @var JWEBuilderFactory $jweFactory */
        $jweFactory = $container->get(JWEBuilderFactory::class);
        $builder = $jweFactory->create(['A256KW'], ['A256CBC-HS512'], []);
        $jwk = new JWK([
            'kty' => 'oct',
            'k' => '3pWc2vAZpHoV7XmCT-z2hWhdQquwQwW5a3XTojbf87c',
        ]);
        $jwk2 = new JWK([
            'kty' => 'oct',
            'k' => '1MVYnFKurkDCueAM6FaMlojPPUMrKitzgzCEt3qrQdc',
        ]);
        $jwe = $builder
            ->create()
            ->withPayload('Hello World!')
            ->withSharedProtectedHeader([
                'alg' => 'A256KW',
                'enc' => 'A256CBC-HS512',
            ])
            ->addRecipient($jwk)
            ->addRecipient($jwk2)
            ->build()
        ;
        static::assertInstanceOf(JWE::class, $jwe);
        // No context, recipient index = 0
        static::assertInstanceOf(JWE::class, $this->loadJWE($serializer->encode($jwe, 'jwe_compact'), $jwk, $recipient));
        static::assertInstanceOf(JWE::class, $this->loadJWE($serializer->encode($jwe, 'jwe_json_flattened'), $jwk, $recipient));
        static::assertInstanceOf(JWE::class, $this->loadJWE($serializer->encode($jwe, 'jwe_json_general'), $jwk, $recipient));
        static::assertEquals(0, $recipient);
        // With context, recipient index = 0
        static::assertInstanceOf(JWE::class, $this->loadJWE($serializer->encode($jwe, 'jwe_compact', ['recipient_index' => 0]), $jwk, $recipient));
        static::assertInstanceOf(JWE::class, $this->loadJWE($serializer->encode($jwe, 'jwe_json_flattened', ['recipient_index' => 0]), $jwk, $recipient));
        static::assertInstanceOf(JWE::class, $this->loadJWE($serializer->encode($jwe, 'jwe_json_general', ['recipient_index' => 0]), $jwk, $recipient));
        static::assertEquals(0, $recipient);
        // With context, recipient index = 1
        static::assertInstanceOf(JWE::class, $this->loadJWE($serializer->encode($jwe, 'jwe_compact', ['recipient_index' => 1]), $jwk2, $recipient));
        static::assertInstanceOf(JWE::class, $this->loadJWE($serializer->encode($jwe, 'jwe_json_flattened', ['recipient_index' => 1]), $jwk2, $recipient));
        static::assertInstanceOf(JWE::class, $this->loadJWE($serializer->encode($jwe, 'jwe_json_general', ['recipient_index' => 1]), $jwk2, $recipient));
        static::assertEquals(1, $recipient);
    }

    /**
     * @test
     */
    public function jWEEncoderSupportsCustomSerializerManager()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        $jweSerializerManager = new JWESerializerManager([
            new CompactSerializer(),
        ]);
        $serializer = new JWEEncoder($container->get(JWESerializerManagerFactory::class), $jweSerializerManager);
        /** @var JWEBuilderFactory $jweFactory */
        $jweFactory = $container->get(JWEBuilderFactory::class);
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
        static::assertTrue($serializer->supportsEncoding('jwe_compact'));
        static::assertFalse($serializer->supportsEncoding('jwe_json_flattened'));
        static::assertFalse($serializer->supportsEncoding('jwe_json_general'));
        static::assertTrue($serializer->supportsDecoding('jwe_compact'));
        static::assertFalse($serializer->supportsDecoding('jwe_json_flattened'));
        static::assertFalse($serializer->supportsDecoding('jwe_json_general'));
        static::assertInstanceOf(JWE::class, $serializer->decode($this->serializeJWE($jwe, 'jwe_compact', 0), 'jwe_compact'));
        static::assertInstanceOf(JWE::class, $this->loadJWE($serializer->encode($jwe, 'jwe_compact'), $jwk, $recipient));
    }

    /**
     * @test
     */
    public function jWEEncoderShouldThrowOnUnsupportedFormatWhenEncoding()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        $jweSerializerManager = new JWESerializerManager([
            new CompactSerializer(),
        ]);
        $serializer = new JWEEncoder($container->get(JWESerializerManagerFactory::class), $jweSerializerManager);
        /** @var JWEBuilderFactory $jweFactory */
        $jweFactory = $container->get(JWEBuilderFactory::class);
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
        static::assertInstanceOf(JWE::class, $this->loadJWE($serializer->encode($jwe, 'jwe_compact'), $jwk, $recipient));
        $this->expectExceptionMessage('Cannot encode JWE to jwe_json_flattened format.');
        $serializer->encode($jwe, 'jwe_json_flattened');
    }

    /**
     * @test
     */
    public function jWEEncoderShouldThrowOnUnsupportedFormatWhenDecoding()
    {
        $client = static::createClient();
        $container = $client->getContainer();
        $jweSerializerManager = new JWESerializerManager([
            new CompactSerializer(),
        ]);
        $serializer = new JWEEncoder($container->get(JWESerializerManagerFactory::class), $jweSerializerManager);
        /** @var JWEBuilderFactory $jweFactory */
        $jweFactory = $container->get(JWEBuilderFactory::class);
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
        static::assertInstanceOf(JWE::class, $serializer->decode($this->serializeJWE($jwe, 'jwe_compact', 0), 'jwe_compact'));
        $this->expectExceptionMessage('Cannot decode JWE from jwe_json_flattened format.');
        $serializer->decode($this->serializeJWE($jwe, 'jwe_json_flattened', 0), 'jwe_json_flattened');
    }

    /**
     * Serialize JWKE.
     *
     * Use the JWESerializerManager to serialize a JWE.
     */
    private function serializeJWE(JWE $jwe, string $format, ?int $recipientIndex = 0): string
    {
        /** @var JWESerializerManagerFactory $jweSerializerManagerFactory */
        $jweSerializerManagerFactory = static::createClient()->getContainer()->get(JWESerializerManagerFactory::class);
        /** @var JWESerializerManager $jweSerializerManager */
        $jweSerializerManager = $jweSerializerManagerFactory->create($jweSerializerManagerFactory->names());

        return $jweSerializerManager->serialize($format, $jwe, $recipientIndex);
    }

    /**
     * Load/unserialize JWE.
     *
     * Use the JWELoader to load a JWE from a string.
     */
    private function loadJWE(string $token, JWK $jwk, ?int &$recipientIndex): JWE
    {
        $client = static::createClient();
        $container = $client->getContainer();
        /** @var JWESerializerManagerFactory $jweSerializerManagerFactory */
        $jweSerializerManagerFactory = $container->get(JWESerializerManagerFactory::class);
        /** @var JWELoaderFactory $jweLoaderFactory */
        $jweLoaderFactory = $container->get(JWELoaderFactory::class);
        $loader = $jweLoaderFactory->create($jweSerializerManagerFactory->names(), ['A256KW'], ['A256CBC-HS512'], []);

        return $loader->loadAndDecryptWithKey($token, $jwk, $recipientIndex);
    }
}
