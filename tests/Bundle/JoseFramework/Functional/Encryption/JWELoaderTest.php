<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\Functional\Encryption;

use PHPUnit\Framework\Attributes\Test;
use Jose\Bundle\JoseFramework\Services\JWELoaderFactory as JWELoaderFactoryAlias;
use Jose\Component\Encryption\JWEBuilderFactory;
use Jose\Component\Encryption\JWELoader;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * @internal
 */
final class JWELoaderTest extends WebTestCase
{
    protected function setUp(): void
    {
        if (! class_exists(JWEBuilderFactory::class)) {
            static::markTestSkipped('The component "web-token/jwt-encryption" is not installed.');
        }
    }

    #[Test]
    public static function theJWELoaderFactoryIsAvailable(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertInstanceOf(ContainerInterface::class, $container);
        static::assertTrue($container->has(JWELoaderFactoryAlias::class));
    }

    #[Test]
    public static function theWELoaderFactoryCanCreateAJWELoader(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertInstanceOf(ContainerInterface::class, $container);

        $jweLoaderFactory = $container->get(JWELoaderFactoryAlias::class);
        static::assertInstanceOf(JWELoaderFactoryAlias::class, $jweLoaderFactory);

        $jwe = $jweLoaderFactory->create(['jwe_compact'], ['RSA1_5'], ['A256GCM'], ['DEF']);

        static::assertSame(['jwe_compact'], $jwe->getSerializerManager()->names());
        static::assertSame(['RSA1_5'], $jwe->getJweDecrypter()->getKeyEncryptionAlgorithmManager()->list());
        static::assertSame(['A256GCM'], $jwe->getJweDecrypter()->getContentEncryptionAlgorithmManager()->list());
        static::assertSame(['DEF'], $jwe->getJweDecrypter()->getCompressionMethodManager()->list());
    }

    #[Test]
    public static function aJWELoaderCanBeDefinedUsingTheConfigurationFile(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertInstanceOf(ContainerInterface::class, $container);
        static::assertTrue($container->has('jose.jwe_loader.jwe_loader1'));

        $jwe = $container->get('jose.jwe_loader.jwe_loader1');
        static::assertInstanceOf(JWELoader::class, $jwe);
    }

    #[Test]
    public static function aJWELoaderCanBeDefinedFromAnotherBundleUsingTheHelper(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertInstanceOf(ContainerInterface::class, $container);
        static::assertTrue($container->has('jose.jwe_loader.jwe_loader2'));

        $jwe = $container->get('jose.jwe_loader.jwe_loader2');
        static::assertInstanceOf(JWELoader::class, $jwe);
    }
}
