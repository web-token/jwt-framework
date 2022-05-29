<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\Functional\Serializer;

use Jose\Bundle\JoseFramework\Serializer\JWESerializer;
use Jose\Bundle\JoseFramework\Services\JWEBuilderFactory;
use Jose\Component\Core\JWK;
use Jose\Component\Encryption\JWE;
use Jose\Component\Encryption\JWEBuilderFactory as BaseJWEBuilderFactory;
use Jose\Component\Encryption\Serializer\JWESerializerManager;
use Jose\Component\Encryption\Serializer\JWESerializerManagerFactory;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\Serializer\Normalizer\DenormalizerInterface;
use Symfony\Component\Serializer\Normalizer\NormalizerInterface;
use Symfony\Component\Serializer\Serializer;

/**
 * @internal
 */
final class JWESerializerTest extends KernelTestCase
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
    public function theJWESerializerSupportsAllFormatsByDefault(string $format, string $serializerId): void
    {
        $container = static::getContainer();
        $serializer = $container->get($serializerId);
        static::assertInstanceOf(DenormalizerInterface::class, $serializer);
        static::assertTrue($serializer->supportsDenormalization(null, JWE::class, $format));
    }

    /**
     * @test
     */
    public function aJWECannotBeNormalized(): void
    {
        $container = static::getContainer();
        $serializerManagerFactory = $container->get(JWESerializerManagerFactory::class);
        static::assertInstanceOf(JWESerializerManagerFactory::class, $serializerManagerFactory);
        $serializer = new JWESerializer($serializerManagerFactory);

        static::assertNotInstanceOf(NormalizerInterface::class, $serializer);
        static::assertFalse(method_exists($serializer, 'supportsNormalization'));
    }

    /**
     * @test
     * @dataProvider jweFormatDataProvider
     */
    public function theJWEDenormalizerPassesThrough(string $format, string $serializerId): void
    {
        $container = static::getContainer();
        $serializer = $container->get($serializerId);
        static::assertInstanceOf(DenormalizerInterface::class, $serializer);

        ['jwe' => $jwe] = $this->createJWE();

        static::assertTrue($serializer->supportsDenormalization($jwe, JWE::class, $format));
        static::assertSame($jwe, $serializer->denormalize($jwe, JWE::class, $format));
    }

    public function serializerServiceDataProvider(): array
    {
        return [
            'indirect serializer' => ['serializer'],
            'direct serializer' => [JWESerializer::class],
        ];
    }

    public function jweFormatDataProvider(): array
    {
        return [
            'jwe_compact with indirect serializer' => ['jwe_compact', 'serializer'],
            'jwe_compact with direct serializer' => ['jwe_compact', JWESerializer::class],
            'jwe_json_flattened with indirect serializer' => ['jwe_json_flattened', 'serializer'],
            'jwe_json_flattened with direct serializer' => ['jwe_json_flattened', JWESerializer::class],
            'jwe_json_general with indirect serializer' => ['jwe_json_general', 'serializer'],
            'jwe_json_general with direct serializer' => ['jwe_json_general', JWESerializer::class],
        ];
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
