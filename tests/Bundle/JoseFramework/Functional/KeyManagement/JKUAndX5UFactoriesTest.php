<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\Functional\KeyManagement;

use PHPUnit\Framework\Attributes\Test;
use Jose\Component\KeyManagement\JKUFactory;
use Jose\Component\KeyManagement\X5UFactory;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * @internal
 */
final class JKUAndX5UFactoriesTest extends WebTestCase
{
    protected function setUp(): void
    {
        if (! class_exists(JKUFactory::class)) {
            static::markTestSkipped('The component "web-token/jwt-key-mgmt" is not installed.');
        }
    }

    #[Test]
    public static function theJKUFactoryServiceIsAvailable(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();

        $container = $client->getContainer();
        static::assertInstanceOf(ContainerInterface::class, $container);
        static::assertTrue($container->has(JKUFactory::class));
    }

    #[Test]
    public static function theX5UFactoryServiceIsAvailable(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();

        $container = $client->getContainer();
        static::assertInstanceOf(ContainerInterface::class, $container);
        static::assertTrue($container->has(X5UFactory::class));
    }
}
