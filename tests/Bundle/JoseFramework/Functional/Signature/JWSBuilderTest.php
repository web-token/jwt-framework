<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\Functional\Signature;

use Jose\Bundle\JoseFramework\Services\JWSBuilder;
use Jose\Bundle\JoseFramework\Services\JWSBuilderFactory as JWSBuilderFactoryService;
use Jose\Component\Signature\JWSBuilderFactory;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

/**
 * @internal
 */
final class JWSBuilderTest extends WebTestCase
{
    #[Test]
    public static function jWSBuilderFactoryIsAvailable(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertTrue($container->has(JWSBuilderFactoryService::class));
    }

    #[Test]
    public static function jWSBuilderFactoryCanCreateAJWSBuilder(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();

        /** @var JWSBuilderFactory $jwsFactory */
        $jwsFactory = $container->get(JWSBuilderFactoryService::class);

        $jws = $jwsFactory->create(['none']);

        static::assertInstanceOf(JWSBuilder::class, $jws);
    }

    #[Test]
    public static function jWSBuilderFromConfigurationIsAvailable(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertTrue($container->has('jose.jws_builder.builder1'));

        $jws = $container->get('jose.jws_builder.builder1');
        static::assertInstanceOf(JWSBuilder::class, $jws);
    }

    #[Test]
    public static function jWSBuilderFromExternalBundleExtensionIsAvailable(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertTrue($container->has('jose.jws_builder.builder2'));

        $jws = $container->get('jose.jws_builder.builder2');
        static::assertInstanceOf(JWSBuilder::class, $jws);
    }
}
