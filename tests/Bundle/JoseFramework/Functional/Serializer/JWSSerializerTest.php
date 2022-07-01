<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\Functional\Serializer;

use Jose\Bundle\JoseFramework\Serializer\JWSSerializer;
use Jose\Bundle\JoseFramework\Services\JWSBuilderFactory;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSBuilderFactory as BaseJWSBuilderFactory;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use Jose\Component\Signature\Serializer\JWSSerializerManagerFactory;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\Serializer\Normalizer\DenormalizerInterface;
use Symfony\Component\Serializer\Normalizer\NormalizerInterface;
use Symfony\Component\Serializer\Serializer;

/**
 * @internal
 */
final class JWSSerializerTest extends KernelTestCase
{
    protected function setUp(): void
    {
        if (! class_exists(BaseJWSBuilderFactory::class)) {
            static::markTestSkipped('The component "web-token/jwt-signature" is not installed.');
        }
        if (! class_exists(Serializer::class)) {
            static::markTestSkipped('The component "symfony/serializer" is not installed.');
        }
    }

    /**
     * @test
     * @dataProvider jwsFormatDataProvider
     */
    public function theJWSSerializerSupportsAllFormatsByDefault(string $format, string $serializerId): void
    {
        $container = static::getContainer();
        $serializer = $container->get($serializerId);
        static::assertInstanceOf(DenormalizerInterface::class, $serializer);
        static::assertTrue($serializer->supportsDenormalization(null, JWS::class, $format));
    }

    /**
     * @test
     */
    public function aJWSCannotBeNormalized(): void
    {
        $container = static::getContainer();
        $serializerManagerFactory = $container->get(JWSSerializerManagerFactory::class);
        static::assertInstanceOf(JWSSerializerManagerFactory::class, $serializerManagerFactory);
        $serializer = new JWSSerializer($serializerManagerFactory);

        static::assertNotInstanceOf(NormalizerInterface::class, $serializer);
        static::assertFalse(method_exists($serializer, 'supportsNormalization'));
    }

    /**
     * @test
     * @dataProvider jwsFormatDataProvider
     */
    public function theJWSDenormalizerPassesThrough(string $format, string $serializerId): void
    {
        $container = static::getContainer();
        $serializer = $container->get($serializerId);
        static::assertInstanceOf(DenormalizerInterface::class, $serializer);

        ['jws' => $jws] = $this->createJWS();

        static::assertTrue($serializer->supportsDenormalization($jws, JWS::class, $format));
        static::assertSame($jws, $serializer->denormalize($jws, JWS::class, $format));
    }

    public function serializerServiceDataProvider(): array
    {
        return [
            'indirect serializer' => ['serializer'],
            'direct serializer' => [JWSSerializer::class],
        ];
    }

    public function jwsFormatDataProvider(): array
    {
        return [
            'jws_compact with indirect serializer' => ['jws_compact', 'serializer'],
            'jws_compact with direct serializer' => ['jws_compact', JWSSerializer::class],
            'jws_json_flattened with indirect serializer' => ['jws_json_flattened', 'serializer'],
            'jws_json_flattened with direct serializer' => ['jws_json_flattened', JWSSerializer::class],
            'jws_json_general with indirect serializer' => ['jws_json_general', 'serializer'],
            'jws_json_general with direct serializer' => ['jws_json_general', JWSSerializer::class],
        ];
    }

    private function createJWS(bool $multiSignature = false): array
    {
        $container = static::getContainer();
        $jwsFactory = $container->get(JWSBuilderFactory::class);
        static::assertInstanceOf(JWSBuilderFactory::class, $jwsFactory);
        $jwsSerializerManagerFactory = $container->get(JWSSerializerManagerFactory::class);
        static::assertInstanceOf(JWSSerializerManagerFactory::class, $jwsSerializerManagerFactory);
        $jwsSerializerManager = $jwsSerializerManagerFactory->create($jwsSerializerManagerFactory->names());
        static::assertInstanceOf(JWSSerializerManager::class, $jwsSerializerManager);

        $builder = $jwsFactory->create(['HS256']);

        $jwk = new JWK([
            'kty' => 'oct',
            'k' => '3pWc2vAZpHoV7XmCT-z2hWhdQquwQwW5a3XTojbf87c',
        ]);
        $jwk2 = $multiSignature
            ? new JWK([
                'kty' => 'oct',
                'k' => '45d2aGyfduzrkcmL7duvUTDTlXS2s3u4uMER2feQruU',
            ])
            : null;

        $jwsBuilder = $builder
            ->create()
            ->withPayload('Hello World!')
            ->addSignature($jwk, [
                'alg' => 'HS256',
            ])
        ;

        if ($multiSignature) {
            $jwsBuilder = $jwsBuilder->addSignature($jwk2, [
                'alg' => 'HS256',
            ]);
        }

        $jws = $jwsBuilder->build();

        return [
            'jwk' => $jwk,
            'jwk2' => $jwk2,
            'jws' => $jws,
            'alg' => 'HS256',
            'jws_compact' => $jwsSerializerManager->serialize('jws_compact', $jws),
            'jws_json_flattened' => $jwsSerializerManager->serialize('jws_json_flattened', $jws),
            'jws_json_general' => $jwsSerializerManager->serialize('jws_json_general', $jws),
        ];
    }
}
