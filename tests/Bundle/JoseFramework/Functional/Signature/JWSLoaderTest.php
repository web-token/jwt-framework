<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\Functional\Signature;

use Jose\Bundle\JoseFramework\Services\JWSLoaderFactory as JWSLoaderFactoryService;
use Jose\Component\Signature\JWSLoader;
use Jose\Component\Signature\JWSLoaderFactory;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

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
}
