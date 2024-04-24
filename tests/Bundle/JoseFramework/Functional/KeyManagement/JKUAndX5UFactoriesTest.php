<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\Functional\KeyManagement;

use Jose\Component\KeyManagement\JKUFactory;
use Jose\Component\KeyManagement\X5UFactory;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

/**
 * @internal
 */
final class JKUAndX5UFactoriesTest extends WebTestCase
{
    #[Test]
    public static function theJKUFactoryServiceIsAvailable(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();

        $container = $client->getContainer();
        static::assertTrue($container->has(JKUFactory::class));
    }

    #[Test]
    public static function theX5UFactoryServiceIsAvailable(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();

        $container = $client->getContainer();
        static::assertTrue($container->has(X5UFactory::class));
    }
}
