<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\Functional\KeyManagement;

use Jose\Component\Console\RsaKeyGeneratorCommand;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\KeyManagement\JWKFactoryInterface;
use Jose\Tests\Bundle\JoseFramework\WebTestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * The key factory is a service of the bundle and is aliased with its interface, so that it can be autowired and
 * decorated. The console commands that generate or load keys receive it instead of calling the static methods.
 *
 * @internal
 */
final class JWKFactoryServiceTest extends WebTestCase
{
    #[Test]
    public static function theKeyFactoryIsAvailableAsAService(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();

        $container = $client->getContainer();

        static::assertTrue($container->has(JWKFactory::class));
        static::assertInstanceOf(JWKFactoryInterface::class, $container->get(JWKFactory::class));
    }

    #[Test]
    public static function theKeyFactoryIsAliasedWithItsInterface(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();

        $container = $client->getContainer();

        static::assertTrue($container->has(JWKFactoryInterface::class));
        static::assertInstanceOf(JWKFactoryInterface::class, $container->get(JWKFactoryInterface::class));
    }

    #[Test]
    public static function theGeneratorCommandsReceiveTheKeyFactory(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();

        $container = $client->getContainer();

        static::assertTrue($container->has(RsaKeyGeneratorCommand::class));
        static::assertInstanceOf(RsaKeyGeneratorCommand::class, $container->get(RsaKeyGeneratorCommand::class));
    }
}
