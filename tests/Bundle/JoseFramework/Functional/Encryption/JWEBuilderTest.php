<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\Functional\Encryption;

use Jose\Bundle\JoseFramework\Services\JWEBuilder;
use Jose\Bundle\JoseFramework\Services\JWEBuilderFactory as JWEBuilderFactoryService;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

/**
 * @internal
 */
final class JWEBuilderTest extends WebTestCase
{
    #[Test]
    public static function theJWEBuilderFactoryIsAvailable(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertTrue($container->has(JWEBuilderFactoryService::class));
    }

    #[Test]
    public static function theJWEBuilderFactoryCanCreateAJWEBuilder(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();

        $jweFactory = $container->get(JWEBuilderFactoryService::class);
        static::assertInstanceOf(JWEBuilderFactoryService::class, $jweFactory);

        $jweFactory->create(['RSA1_5', 'A256GCM']);
    }

    #[Test]
    public static function aJWEBuilderCanBeDefinedUsingTheConfigurationFile(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertTrue($container->has('jose.jwe_builder.builder1'));

        $jwe = $container->get('jose.jwe_builder.builder1');
        static::assertInstanceOf(JWEBuilder::class, $jwe);
    }

    #[Test]
    public static function aJWEBuilderCanBeDefinedFromAnotherBundleUsingTheHelper(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertTrue($container->has('jose.jwe_builder.builder2'));

        $jwe = $container->get('jose.jwe_builder.builder2');
        static::assertInstanceOf(JWEBuilder::class, $jwe);
    }
}
