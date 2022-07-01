<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\Functional\Serializer;

use Jose\Bundle\JoseFramework\Serializer\JWEEncoder;
use Jose\Bundle\JoseFramework\Services\JWEBuilderFactory;
use Jose\Bundle\JoseFramework\Services\JWELoaderFactory;
use Jose\Component\Core\JWK;
use Jose\Component\Encryption\JWE;
use Jose\Component\Encryption\JWEBuilderFactory as BaseJWEBuilderFactory;
use Jose\Component\Encryption\Serializer\CompactSerializer;
use Jose\Component\Encryption\Serializer\JWESerializerManager;
use Jose\Component\Encryption\Serializer\JWESerializerManagerFactory;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\Serializer\Encoder\DecoderInterface;
use Symfony\Component\Serializer\Encoder\EncoderInterface;
use Symfony\Component\Serializer\Serializer;

/**
 * @internal
 */
final class JWEEncoderTest extends KernelTestCase
{
    protected function setUp(): void
    {
        if (! class_exists(BaseJWEBuilderFactory::class)) {
            static::markTestSkipped('The component "web-token/jwt-encryption" is not installed.');
        }
        if (! class_exists(Serializer::class)) {
            static::markTestSkipped('The component "symfony/serializer" is not installed.');
        }
    }

    /**
     * @test
     * @dataProvider jweFormatDataProvider
     */
    public function theJWEEncoderSupportsAllFormatsByDefault(string $format, string $serializerId): void
    {
        $container = static::getContainer();
        $serializer = $container->get($serializerId);
        static::assertInstanceOf(EncoderInterface::class, $serializer);
        static::assertTrue($serializer->supportsEncoding($format));
        static::assertInstanceOf(DecoderInterface::class, $serializer);
        static::assertTrue($serializer->supportsDecoding($format));
    }

    /**
     * @test
     * @dataProvider jweFormatDataProvider
     */
    public function aJWECanBeEncodedInAllFormats(string $format, string $serializerId): void
    {
        $container = static::getContainer();
        $serializer = $container->get($serializerId);
        static::assertInstanceOf(EncoderInterface::class, $serializer);

        ['jwk' => $jwk, 'jwe' => $jwe] = $this->createJWE();

        $jweString = $serializer->encode($jwe, $format);
        $this->assertEncodedJWEValid($jweString, $format);
        static::assertSame(0, $this->loadJWE($jweString, $jwk));
    }

    /**
     * @test
     * @dataProvider jweFormatDataProvider
     */
    public function aJWECanBeEncodedWithSpecificRecipient(string $format, string $serializerId): void
    {
        $container = static::getContainer();
        $serializer = $container->get($serializerId);
        static::assertInstanceOf(EncoderInterface::class, $serializer);

        ['jwk' => $jwk, 'jwk2' => $jwk2, 'jwe' => $jwe] = $this->createJWE();

        // Recipient index = 0
        $jweString = $serializer->encode($jwe, $format, [
            'recipient_index' => 0,
        ]);
        $this->assertEncodedJWEValid($jweString, $format);
        static::assertSame(0, $this->loadJWE($jweString, $jwk));
        unset($recipient);

        // Recipient index = 1
        $jweString = $serializer->encode($jwe, $format, [
            'recipient_index' => 1,
        ]);
        $this->assertEncodedJWEValid($jweString, $format);
        static::assertSame($format === 'jwe_json_general' ? 1 : 0, $this->loadJWE($jweString, $jwk2));
    }

    /**
     * @test
     * @dataProvider encoderServiceDataProvider
     */
    public function theJWEEncoderThrowsOnNonExistingRecipient(string $serializerId): void
    {
        $container = static::getContainer();
        $serializer = $container->get($serializerId);
        static::assertInstanceOf(EncoderInterface::class, $serializer);

        ['jwe' => $jwe] = $this->createJWE();

        $this->expectExceptionMessage(sprintf('Cannot encode JWE to %s format.', 'jwe_compact'));
        $serializer->encode($jwe, 'jwe_compact', [
            'recipient_index' => 2,
        ]);
    }

    /**
     * @test
     */
    public function aJWECanBeEncodedWithCustomSerializerManager(): void
    {
        $container = static::getContainer();
        $jweSerializerManager = new JWESerializerManager([new CompactSerializer()]);
        $jweSerializerManagerFactory = $container->get(JWESerializerManagerFactory::class);
        static::assertInstanceOf(JWESerializerManagerFactory::class, $jweSerializerManagerFactory);
        $serializer = new JWEEncoder($jweSerializerManagerFactory, $jweSerializerManager);
        static::assertInstanceOf(EncoderInterface::class, $serializer);

        ['jwk' => $jwk, 'jwe' => $jwe] = $this->createJWE();

        static::assertTrue($serializer->supportsEncoding('jwe_compact'));
        static::assertFalse($serializer->supportsEncoding('jwe_json_flattened'));
        static::assertFalse($serializer->supportsEncoding('jwe_json_general'));
        static::assertTrue($serializer->supportsDecoding('jwe_compact'));
        static::assertFalse($serializer->supportsDecoding('jwe_json_flattened'));
        static::assertFalse($serializer->supportsDecoding('jwe_json_general'));

        $jweString = $serializer->encode($jwe, 'jwe_compact');
        $this->assertEncodedJWEValid($jweString, 'jwe_compact');
        static::assertSame(0, $this->loadJWE($jweString, $jwk));
    }

    /**
     * @test
     */
    public function theJWEEncoderShouldThrowOnUnsupportedFormatWhenEncoding(): void
    {
        $container = static::getContainer();
        $jweSerializerManager = new JWESerializerManager([new CompactSerializer()]);
        $jweSerializerManagerFactory = $container->get(JWESerializerManagerFactory::class);
        static::assertInstanceOf(JWESerializerManagerFactory::class, $jweSerializerManagerFactory);
        $serializer = new JWEEncoder($jweSerializerManagerFactory, $jweSerializerManager);
        static::assertInstanceOf(EncoderInterface::class, $serializer);

        ['jwe' => $jwe] = $this->createJWE();

        $this->expectExceptionMessage('Cannot encode JWE to jwe_json_flattened format.');
        $serializer->encode($jwe, 'jwe_json_flattened');
    }

    /**
     * @test
     * @dataProvider jweFormatDataProvider
     */
    public function aJWECanBeDecodedInAllFormats(string $format, string $serializerId): void
    {
        $container = static::getContainer();
        $serializer = $container->get($serializerId);
        static::assertInstanceOf(DecoderInterface::class, $serializer);

        $jweData = $this->createJWE();

        $jwe = $serializer->decode($jweData[$format], $format);
        static::assertInstanceOf(JWE::class, $jwe);
    }

    /**
     * @test
     */
    public function theJWEEncoderShouldThrowOnUnsupportedFormatWhenDecoding(): void
    {
        $container = static::getContainer();
        $jweSerializerManager = new JWESerializerManager([new CompactSerializer()]);
        $jweSerializerManagerFactory = $container->get(JWESerializerManagerFactory::class);
        static::assertInstanceOf(JWESerializerManagerFactory::class, $jweSerializerManagerFactory);
        $serializer = new JWEEncoder($jweSerializerManagerFactory, $jweSerializerManager);
        static::assertInstanceOf(EncoderInterface::class, $serializer);

        ['jwe_json_flattened' => $jweString] = $this->createJWE();

        $this->expectExceptionMessage('Cannot decode JWE from jwe_json_flattened format.');
        $serializer->decode($jweString, 'jwe_json_flattened');
    }

    public function encoderServiceDataProvider(): array
    {
        return [
            'indirect serializer' => ['serializer'],
            'direct serializer' => [JWEEncoder::class],
        ];
    }

    public function jweFormatDataProvider(): array
    {
        return [
            'jwe_compact with indirect serializer' => ['jwe_compact', 'serializer'],
            'jwe_compact with direct serializer' => ['jwe_compact', JWEEncoder::class],
            'jwe_json_flattened with indirect serializer' => ['jwe_json_flattened', 'serializer'],
            'jwe_json_flattened with direct serializer' => ['jwe_json_flattened', JWEEncoder::class],
            'jwe_json_general with indirect serializer' => ['jwe_json_general', 'serializer'],
            'jwe_json_general with direct serializer' => ['jwe_json_general', JWEEncoder::class],
        ];
    }

    private function assertEncodedJWEValid(string $jwe, string $format): void
    {
        if ($format === 'jwe_compact') {
            static::assertMatchesRegularExpression('/^.+\..+\..+$/', $jwe);
            static::assertStringStartsWith('eyJhbGciOiJBMjU2S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0', $jwe);

            return;
        }

        static::assertJson($jwe);
    }

    private function loadJWE(string $jwe, JWK $jwk): int
    {
        $recipient = null;
        $container = static::getContainer();
        $jweSerializerManagerFactory = $container->get(JWESerializerManagerFactory::class);
        static::assertInstanceOf(JWESerializerManagerFactory::class, $jweSerializerManagerFactory);
        $jweLoaderFactory = $container->get(JWELoaderFactory::class);
        static::assertInstanceOf(JWELoaderFactory::class, $jweLoaderFactory);
        $loader = $jweLoaderFactory->create($jweSerializerManagerFactory->names(), ['A256KW'], ['A256CBC-HS512'], []);

        $loader->loadAndDecryptWithKey($jwe, $jwk, $recipient);

        return $recipient;
    }

    private function createJWE(): array
    {
        $container = static::getContainer();
        $jweFactory = $container->get(JWEBuilderFactory::class);
        static::assertInstanceOf(JWEBuilderFactory::class, $jweFactory);
        $jweSerializerManagerFactory = $container->get(JWESerializerManagerFactory::class);
        static::assertInstanceOf(JWESerializerManagerFactory::class, $jweSerializerManagerFactory);
        $jweSerializerManager = $jweSerializerManagerFactory->create($jweSerializerManagerFactory->names());
        static::assertInstanceOf(JWESerializerManager::class, $jweSerializerManager);

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

        return [
            'jwk' => $jwk,
            'jwk2' => $jwk2,
            'jwe' => $jwe,
            'alg' => 'A256KW',
            'enc' => 'A256CBC-HS512',
            'jwe_compact' => $jweSerializerManager->serialize('jwe_compact', $jwe),
            'jwe_json_flattened' => $jweSerializerManager->serialize('jwe_json_flattened', $jwe),
            'jwe_json_general' => $jweSerializerManager->serialize('jwe_json_general', $jwe),
        ];
    }
}
