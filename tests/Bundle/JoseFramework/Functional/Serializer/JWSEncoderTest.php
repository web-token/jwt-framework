<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\Functional\Serializer;

use Jose\Bundle\JoseFramework\Serializer\JWSEncoder;
use Jose\Bundle\JoseFramework\Services\JWSBuilderFactory;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSBuilderFactory as BaseJWSBuilderFactory;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use Jose\Component\Signature\Serializer\JWSSerializerManagerFactory;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\Serializer\Encoder\DecoderInterface;
use Symfony\Component\Serializer\Encoder\EncoderInterface;
use Symfony\Component\Serializer\Serializer;

/**
 * @internal
 */
final class JWSEncoderTest extends KernelTestCase
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
        static::assertInstanceOf(EncoderInterface::class, $serializer);
        static::assertTrue($serializer->supportsEncoding($format));
        static::assertInstanceOf(DecoderInterface::class, $serializer);
        static::assertTrue($serializer->supportsDecoding($format));
    }

    /**
     * @test
     * @dataProvider jwsFormatDataProvider
     */
    public function aJWSCanBeEncodedInAllFormats(string $format, string $serializerId): void
    {
        $container = static::getContainer();
        $serializer = $container->get($serializerId);
        static::assertInstanceOf(EncoderInterface::class, $serializer);

        ['jws' => $jws] = $this->createJWS(true);

        $jwsString = $serializer->encode($jws, $format);
        $expected = [
            'jws_compact' => 'eyJhbGciOiJIUzI1NiJ9.SGVsbG8gV29ybGQh.qTzr2HflJbt-MDo1Ye7i5W85avH4hrhvb1U6tbd_mzY',
            'jws_json_flattened' => '{"payload":"SGVsbG8gV29ybGQh","protected":"eyJhbGciOiJIUzI1NiJ9","signature":"qTzr2HflJbt-MDo1Ye7i5W85avH4hrhvb1U6tbd_mzY"}',
            'jws_json_general' => '{"payload":"SGVsbG8gV29ybGQh","signatures":[{"signature":"qTzr2HflJbt-MDo1Ye7i5W85avH4hrhvb1U6tbd_mzY","protected":"eyJhbGciOiJIUzI1NiJ9"},{"signature":"ZIKPsa3NtNoACjvh6fhfg6PZgmKiuss_9sDPtMZxtNU","protected":"eyJhbGciOiJIUzI1NiJ9"}]}',
        ];
        static::assertSame($expected[$format], $jwsString);
    }

    /**
     * @test
     * @dataProvider jwsFormatDataProvider
     */
    public function aJWSCanBeEncodedWithSpecificSignature(string $format, string $serializerId): void
    {
        $container = static::getContainer();
        $serializer = $container->get($serializerId);
        static::assertInstanceOf(EncoderInterface::class, $serializer);

        ['jws' => $jws] = $this->createJWS(true);

        // Recipient index = 0
        $jwsString = $serializer->encode($jws, $format, [
            'signature_index' => 0,
        ]);
        $expected = [
            'jws_compact' => 'eyJhbGciOiJIUzI1NiJ9.SGVsbG8gV29ybGQh.qTzr2HflJbt-MDo1Ye7i5W85avH4hrhvb1U6tbd_mzY',
            'jws_json_flattened' => '{"payload":"SGVsbG8gV29ybGQh","protected":"eyJhbGciOiJIUzI1NiJ9","signature":"qTzr2HflJbt-MDo1Ye7i5W85avH4hrhvb1U6tbd_mzY"}',
            'jws_json_general' => '{"payload":"SGVsbG8gV29ybGQh","signatures":[{"signature":"qTzr2HflJbt-MDo1Ye7i5W85avH4hrhvb1U6tbd_mzY","protected":"eyJhbGciOiJIUzI1NiJ9"},{"signature":"ZIKPsa3NtNoACjvh6fhfg6PZgmKiuss_9sDPtMZxtNU","protected":"eyJhbGciOiJIUzI1NiJ9"}]}',
        ];
        static::assertSame($expected[$format], $jwsString);

        // Recipient index = 1
        $jwsString = $serializer->encode($jws, $format, [
            'signature_index' => 1,
        ]);
        $expected = [
            'jws_compact' => 'eyJhbGciOiJIUzI1NiJ9.SGVsbG8gV29ybGQh.ZIKPsa3NtNoACjvh6fhfg6PZgmKiuss_9sDPtMZxtNU',
            'jws_json_flattened' => '{"payload":"SGVsbG8gV29ybGQh","protected":"eyJhbGciOiJIUzI1NiJ9","signature":"ZIKPsa3NtNoACjvh6fhfg6PZgmKiuss_9sDPtMZxtNU"}',
            'jws_json_general' => '{"payload":"SGVsbG8gV29ybGQh","signatures":[{"signature":"qTzr2HflJbt-MDo1Ye7i5W85avH4hrhvb1U6tbd_mzY","protected":"eyJhbGciOiJIUzI1NiJ9"},{"signature":"ZIKPsa3NtNoACjvh6fhfg6PZgmKiuss_9sDPtMZxtNU","protected":"eyJhbGciOiJIUzI1NiJ9"}]}',
        ];
        static::assertSame($expected[$format], $jwsString);
    }

    /**
     * @test
     */
    public function aJWSCanBeEncodedWithCustomSerializerManager(): void
    {
        $container = static::getContainer();
        $jwsSerializerManager = new JWSSerializerManager([new CompactSerializer()]);
        $jwsSerializerManagerFactory = $container->get(JWSSerializerManagerFactory::class);
        static::assertInstanceOf(JWSSerializerManagerFactory::class, $jwsSerializerManagerFactory);
        $serializer = new JWSEncoder($jwsSerializerManagerFactory, $jwsSerializerManager);
        static::assertInstanceOf(EncoderInterface::class, $serializer);

        ['jws' => $jws] = $this->createJWS();

        static::assertTrue($serializer->supportsEncoding('jws_compact'));
        static::assertFalse($serializer->supportsEncoding('jws_json_flattened'));
        static::assertFalse($serializer->supportsEncoding('jws_json_general'));
        static::assertTrue($serializer->supportsDecoding('jws_compact'));
        static::assertFalse($serializer->supportsDecoding('jws_json_flattened'));
        static::assertFalse($serializer->supportsDecoding('jws_json_general'));

        static::assertSame(
            'eyJhbGciOiJIUzI1NiJ9.SGVsbG8gV29ybGQh.qTzr2HflJbt-MDo1Ye7i5W85avH4hrhvb1U6tbd_mzY',
            $serializer->encode($jws, 'jws_compact')
        );
    }

    /**
     * @test
     */
    public function theJWSSerializerShouldThrowOnUnsupportedFormatWhenEncoding(): void
    {
        $container = static::getContainer();
        $jwsSerializerManager = new JWSSerializerManager([new CompactSerializer()]);
        $jwsSerializerManagerFactory = $container->get(JWSSerializerManagerFactory::class);
        static::assertInstanceOf(JWSSerializerManagerFactory::class, $jwsSerializerManagerFactory);
        $serializer = new JWSEncoder($jwsSerializerManagerFactory, $jwsSerializerManager);
        static::assertInstanceOf(EncoderInterface::class, $serializer);

        ['jws' => $jws] = $this->createJWS();

        $this->expectExceptionMessage('Cannot encode JWS to jws_json_flattened format.');
        $serializer->encode($jws, 'jws_json_flattened');
    }

    /**
     * @test
     * @dataProvider jwsFormatDataProvider
     */
    public function aJWSCanBeDecodedInAllFormats(string $format, string $serializerId): void
    {
        $container = static::getContainer();
        $serializer = $container->get($serializerId);
        static::assertInstanceOf(DecoderInterface::class, $serializer);

        $jwsData = $this->createJWS();

        $jws = $serializer->decode($jwsData[$format], $format);
        static::assertInstanceOf(JWS::class, $jws);
        static::assertEqualsCanonicalizing($jwsData['jws'], $jws);
    }

    /**
     * @test
     */
    public function theJWSSerializerShouldThrowOnUnsupportedFormatWhenDecoding(): void
    {
        $container = static::getContainer();
        $jwsSerializerManager = new JWSSerializerManager([new CompactSerializer()]);
        $jwsSerializerManagerFactory = $container->get(JWSSerializerManagerFactory::class);
        static::assertInstanceOf(JWSSerializerManagerFactory::class, $jwsSerializerManagerFactory);
        $serializer = new JWSEncoder($jwsSerializerManagerFactory, $jwsSerializerManager);
        static::assertInstanceOf(EncoderInterface::class, $serializer);

        $jwsString = '{"payload":"SGVsbG8gV29ybGQh","protected":"eyJhbGciOiJIUzI1NiJ9","signature":"ZIKPsa3NtNoACjvh6fhfg6PZgmKiuss_9sDPtMZxtNU"}';

        $this->expectExceptionMessage('Cannot decode JWS from jws_json_flattened format.');
        $serializer->decode($jwsString, 'jws_json_flattened');
    }

    public function serializerServiceDataProvider(): array
    {
        return [
            'indirect serializer' => ['serializer'],
            'direct serializer' => [JWSEncoder::class],
        ];
    }

    public function jwsFormatDataProvider(): array
    {
        return [
            'jws_compact with indirect serializer' => ['jws_compact', 'serializer'],
            'jws_compact with direct serializer' => ['jws_compact', JWSEncoder::class],
            'jws_json_flattened with indirect serializer' => ['jws_json_flattened', 'serializer'],
            'jws_json_flattened with direct serializer' => ['jws_json_flattened', JWSEncoder::class],
            'jws_json_general with indirect serializer' => ['jws_json_general', 'serializer'],
            'jws_json_general with direct serializer' => ['jws_json_general', JWSEncoder::class],
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
