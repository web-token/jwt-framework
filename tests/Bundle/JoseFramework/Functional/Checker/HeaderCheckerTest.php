<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\Functional\Checker;

use Jose\Bundle\JoseFramework\Services\HeaderCheckerManagerFactory as HeaderCheckerManagerFactoryService;
use Jose\Component\Checker\HeaderCheckerManagerFactory;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * @internal
 */
final class HeaderCheckerTest extends WebTestCase
{
    protected function setUp(): void
    {
        if (! class_exists(HeaderCheckerManagerFactory::class)) {
            static::markTestSkipped('The component "web-token/jwt-checker" is not installed.');
        }
    }

    /**
     * @test
     */
    public function theHeaderCheckerManagerFactoryIsAvailable(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertInstanceOf(ContainerInterface::class, $container);
        static::assertTrue($container->has(HeaderCheckerManagerFactoryService::class));
    }

    /**
     * @test
     */
    public function theHeaderCheckerManagerFactoryCanCreateAHeaderCheckerManager(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertInstanceOf(ContainerInterface::class, $container);
        $headerCheckerManagerFactory = $container->get(HeaderCheckerManagerFactoryService::class);
        static::assertInstanceOf(HeaderCheckerManagerFactoryService::class, $headerCheckerManagerFactory);

        $aliases = $headerCheckerManagerFactory->aliases();
        $headerCheckerManagerFactory->create($aliases);
    }

    /**
     * @test
     */
    public function aHeaderCheckerCanBeDefinedUsingTheConfigurationFile(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertInstanceOf(ContainerInterface::class, $container);
        static::assertTrue($container->has('jose.header_checker.checker1'));
    }

    /**
     * @test
     */
    public function aHeaderCheckerCanBeDefinedFromAnotherBundleUsingTheHelper(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertInstanceOf(ContainerInterface::class, $container);
        static::assertTrue($container->has('jose.header_checker.checker2'));
    }
}
