<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\Functional\Signature;

use Jose\Bundle\JoseFramework\Services\JWSLoaderFactory as JWSLoaderFactoryService;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\Exception\InvalidTokenException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWSLoader;
use Jose\Component\Signature\JWSLoaderFactory;
use Jose\Component\Signature\Serializer\JSONGeneralSerializer;
use Jose\Tests\Bundle\JoseFramework\WebTestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * @internal
 */
final class JWSLoaderTest extends WebTestCase
{
    #[Test]
    public static function theJWSLoaderFactoryIsAvailable(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertTrue($container->has(JWSLoaderFactoryService::class));
    }

    #[Test]
    public static function theWELoaderFactoryCanCreateAJWSLoader(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();

        /** @var JWSLoaderFactory $jwsLoaderFactory */
        $jwsLoaderFactory = $container->get(JWSLoaderFactoryService::class);

        $jws = $jwsLoaderFactory->create(['jws_compact'], ['RS512']);

        static::assertSame(['jws_compact'], $jws->getSerializerManager()->list());
        static::assertSame(['RS512'], $jws->getJwsVerifier()->getSignatureAlgorithmManager()->list());
    }

    #[Test]
    public static function aJWSLoaderCanBeDefinedUsingTheConfigurationFile(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertTrue($container->has('jose.jws_loader.jws_loader1'));

        $jws = $container->get('jose.jws_loader.jws_loader1');
        static::assertInstanceOf(JWSLoader::class, $jws);
    }

    #[Test]
    public static function aJWSLoaderCanBeDefinedFromAnotherBundleUsingTheHelper(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertTrue($container->has('jose.jws_loader.jws_loader2'));

        $jws = $container->get('jose.jws_loader.jws_loader2');
        static::assertInstanceOf(JWSLoader::class, $jws);
    }

    #[Test]
    public static function theMaximumNumberOfSignaturesCanBeSetInTheConfigurationFile(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        $jwsLoader = $container->get('jose.jws_loader.jws_loader_limited');
        static::assertInstanceOf(JWSLoader::class, $jwsLoader);
        $key = new JWK([
            'kty' => 'oct',
            'k' => Base64UrlSafe::encodeUnpadded(random_bytes(32)),
        ]);
        $otherKey = new JWK([
            'kty' => 'oct',
            'k' => Base64UrlSafe::encodeUnpadded(random_bytes(32)),
        ]);
        $jwsBuilder = (new JWSBuilder(new AlgorithmManager([new HS256()])))
            ->withPayload('Live long and prosper.');
        $serializer = new JSONGeneralSerializer();
        $oneSignature = $serializer->serialize($jwsBuilder->addSignature($key, [
            'alg' => 'HS256',
        ])->build());
        $twoSignatures = $serializer->serialize($jwsBuilder->addSignature($otherKey, [
            'alg' => 'HS256',
        ])->addSignature($key, [
            'alg' => 'HS256',
        ])->build());

        static::assertSame(
            'Live long and prosper.',
            $jwsLoader->loadAndVerify($oneSignature, $key)
                ->getJws()
                ->getPayload()
        );
        try {
            $jwsLoader->loadAndVerify($twoSignatures, $key);
        } catch (InvalidTokenException $exception) {
            static::assertSame(
                'The token has too many signatures. The maximum allowed number is 1.',
                $exception->getPrevious()?->getMessage()
            );

            return;
        }
        static::fail('The token has been verified.');
    }
}
