<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\Functional\Serializer;

use Jose\Bundle\JoseFramework\Serializer\JWESerializer;
use Jose\Bundle\JoseFramework\Services\JWEBuilderFactory;
use Jose\Component\Core\JWK;
use Jose\Component\Encryption\JWE;
use Jose\Component\Encryption\Serializer\JWESerializerManager;
use Jose\Component\Encryption\Serializer\JWESerializerManagerFactory;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\Serializer\Normalizer\DenormalizerInterface;
use Symfony\Component\Serializer\Normalizer\NormalizerInterface;

/**
 * @internal
 */
final class JWESerializerTest extends KernelTestCase
{
    #[DataProvider('jweFormatDataProvider')]
    #[Test]
    public function theJWESerializerSupportsAllFormatsByDefault(string $format, string $serializerId): void
    {
        $container = static::getContainer();
        $serializer = $container->get($serializerId);
        static::assertInstanceOf(DenormalizerInterface::class, $serializer);
        static::assertTrue($serializer->supportsDenormalization(null, JWE::class, $format));
    }

    #[Test]
    public static function aJWECannotBeNormalized(): void
    {
        $container = static::getContainer();
        $serializerManagerFactory = $container->get(JWESerializerManagerFactory::class);
        static::assertInstanceOf(JWESerializerManagerFactory::class, $serializerManagerFactory);
        $serializer = new JWESerializer($serializerManagerFactory);

        static::assertNotInstanceOf(NormalizerInterface::class, $serializer);
        static::assertFalse(method_exists($serializer, 'supportsNormalization'));
    }

    #[DataProvider('jweFormatDataProvider')]
    #[Test]
    public function theJWEDenormalizerPassesThrough(string $format, string $serializerId): void
    {
        $container = static::getContainer();
        $serializer = $container->get($serializerId);
        static::assertInstanceOf(DenormalizerInterface::class, $serializer);

        ['jwe' => $jwe] = $this->createJWE();

        static::assertTrue($serializer->supportsDenormalization($jwe, JWE::class, $format));
        static::assertSame($jwe, $serializer->denormalize($jwe, JWE::class, $format));
    }

    public function serializerServiceDataProvider(): iterable
    {
        yield 'indirect serializer' => ['serializer'];
        yield 'direct serializer' => [JWESerializer::class];
    }

    public static function jweFormatDataProvider(): iterable
    {
        yield 'jwe_compact with indirect serializer' => ['jwe_compact', 'serializer'];
        yield 'jwe_compact with direct serializer' => ['jwe_compact', JWESerializer::class];
        yield 'jwe_json_flattened with indirect serializer' => ['jwe_json_flattened', 'serializer'];
        yield 'jwe_json_flattened with direct serializer' => ['jwe_json_flattened', JWESerializer::class];
        yield 'jwe_json_general with indirect serializer' => ['jwe_json_general', 'serializer'];
        yield 'jwe_json_general with direct serializer' => ['jwe_json_general', JWESerializer::class];
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

        $builder = $jweFactory->create(['A256KW', 'A256CBC-HS512']);

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
            ->build();

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
