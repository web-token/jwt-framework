<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\Functional\Checker;

use Jose\Bundle\JoseFramework\Services\HeaderCheckerManagerFactory as HeaderCheckerManagerFactoryService;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

/**
 * @internal
 */
final class HeaderCheckerTest extends WebTestCase
{
    #[Test]
    public static function theHeaderCheckerManagerFactoryIsAvailable(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertTrue($container->has(HeaderCheckerManagerFactoryService::class));
    }

    #[Test]
    public static function theHeaderCheckerManagerFactoryCanCreateAHeaderCheckerManager(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        $headerCheckerManagerFactory = $container->get(HeaderCheckerManagerFactoryService::class);
        static::assertInstanceOf(HeaderCheckerManagerFactoryService::class, $headerCheckerManagerFactory);

        $aliases = $headerCheckerManagerFactory->aliases();
        $headerCheckerManagerFactory->create($aliases);
    }

    #[Test]
    public static function aHeaderCheckerCanBeDefinedUsingTheConfigurationFile(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertTrue($container->has('jose.header_checker.checker1'));
    }

    #[Test]
    public static function aHeaderCheckerCanBeDefinedFromAnotherBundleUsingTheHelper(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertTrue($container->has('jose.header_checker.checker2'));
    }
}
